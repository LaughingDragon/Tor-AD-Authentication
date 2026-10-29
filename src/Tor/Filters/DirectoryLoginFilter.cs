// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OrchardCore.DisplayManagement.Notify;
using OrchardCore.Users;
using OrchardCore.Users.Events;
using OrchardCore.Users.Models;
using Tor.Directory;
using Tor.Services;

namespace Tor.Filters;

/// <summary>
/// Runs on the POST of Orchard's own login form (after its anti-forgery check). Break-glass local
/// accounts go on to Orchard's password login; every other name is a domain sign-in handled here, in
/// the order of Orchard's own login: the login-form events first, then the credential check (here the
/// directory bind and group gate), then Orchard's checks on the user, then the cookie and the events.
/// Every failure looks the same to the user: Orchard's "Invalid login attempt." and the login page;
/// the cause goes only to Tor's audit log.
/// </summary>
public sealed class DirectoryLoginFilter : IAsyncActionFilter
{
    private const string LoginController = "OrchardCore.Users.Controllers.AccountController";
    private const string LoginAction = "LoginPOST";

    private readonly TorOptions _options;
    private readonly IDirectoryAuthenticator _directory;
    private readonly IDirectoryUserSync _sync;
    private readonly LoginThrottle _throttle;
    private readonly SignInAudit _audit;
    private readonly IOrchardSignIn _orchard;
    private readonly IEnumerable<ILoginFormEvent> _loginEvents;
    private readonly IEnumerable<IDirectorySignInHandler> _signInHandlers;
    private readonly ILogger _logger;
    private readonly INotifier _notifier;
    private readonly IHtmlLocalizer H;

    public DirectoryLoginFilter(
        IOptions<TorOptions> options,
        IDirectoryAuthenticator directory,
        IDirectoryUserSync sync,
        LoginThrottle throttle,
        SignInAudit audit,
        IOrchardSignIn orchard,
        IEnumerable<ILoginFormEvent> loginEvents,
        IEnumerable<IDirectorySignInHandler> signInHandlers,
        ILogger<DirectoryLoginFilter> logger,
        INotifier notifier,
        IHtmlLocalizer<DirectoryLoginFilter> localizer)
    {
        _options = options.Value;
        _directory = directory;
        _sync = sync;
        _throttle = throttle;
        _audit = audit;
        _orchard = orchard;
        _loginEvents = loginEvents;
        _signInHandlers = signInHandlers;
        _logger = logger;
        _notifier = notifier;
        H = localizer;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if (context.ActionDescriptor is not ControllerActionDescriptor action ||
            action.ControllerTypeInfo.FullName != LoginController ||
            action.MethodInfo.Name != LoginAction ||
            !context.HttpContext.Request.HasFormContentType)
        {
            await next();
            return;
        }

        var http = context.HttpContext;
        var form = await http.Request.ReadFormAsync(http.RequestAborted);
        var typed = form["LoginForm.UserName"].ToString();
        var password = form["LoginForm.Password"].ToString();
        var client = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var returnUrl = http.Request.Query["returnUrl"].ToString();

        // break-glass: a listed local account, typed as a plain name, keeps Orchard's own login (and its events)
        if (IsLocalAccount(typed))
        {
            var localKey = "local:" + typed.Trim().ToLowerInvariant();
            if (_throttle.IsBlocked(localKey, client))
            {
                // Orchard's action does not run, so its failure event is raised here
                context.Result = await FailAsync(typed, client, "local", "rate limited", user: null, returnUrl);
                return;
            }

            // Orchard answers a good password with a redirect to the return URL, a bad one with the
            // login view again (two-factor would be a redirect to another action: not counted as signed in)
            var executed = await next();
            if (executed.Exception is null && executed.Result is RedirectResult or LocalRedirectResult)
            {
                _throttle.RecordSuccess(localKey);
                _audit.Success(typed, client, "local");
            }
            else
            {
                _throttle.RecordFailure(localKey, client);
                _audit.Failure(typed, client, "local", "local login refused");
            }

            return;
        }

        context.Result = await SignInDirectoryAsync(typed, password, client, returnUrl);
    }

    /// <summary>A directory sign-in: the result is the redirect to the return URL, or the generic failure.</summary>
    internal async Task<IActionResult> SignInDirectoryAsync(string typed, string password, string client, string? returnUrl)
    {
        var account = AccountName.Parse(typed, _options.NetBiosName, _options.Domain);
        var userKey = account?.ThrottleKey ?? typed.Trim().ToLowerInvariant();
        var refusal = new Refusal();

        try
        {
            if (await DirectoryAsync(account, typed, password, client, refusal) is { } signedIn)
            {
                // signed in: only logging and redirect from here
                _throttle.RecordSuccess(userKey);
                _audit.Success(typed, client, "directory " + signedIn.Transport);
                return new LocalRedirectResult(!string.IsNullOrEmpty(returnUrl) && IsLocalUrl(returnUrl) ? returnUrl : "~/");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // anything unexpected fails closed, with the same answer as every other failure
            _logger.LogError("Tor: directory sign-in failed with an error ({Error}).", ex.GetType().Name);
            refusal.Reason = "error " + ex.GetType().Name;
            refusal.Count = true;
        }

        if (refusal.Count)
        {
            _throttle.RecordFailure(userKey, client);
        }

        // the one failure answer, built once for every cause
        return await FailAsync(typed, client, "directory", refusal.Reason ?? "refused", refusal.User, returnUrl);
    }

    /// <summary>Why a directory sign-in was refused, filled in as it goes (the cause is for Tor's log only).</summary>
    private sealed class Refusal
    {
        public string? Reason { get; set; }
        public User? User { get; set; }

        /// <summary>Whether it counts against the user name and client in the throttle.</summary>
        public bool Count { get; set; }
    }

    // the result on success; null with the refusal filled in on any failure
    private async Task<DirectoryResult?> DirectoryAsync(AccountName? account, string typed, string password, string client, Refusal refusal)
    {
        var userKey = account?.ThrottleKey ?? typed.Trim().ToLowerInvariant();

        // (a) Orchard's login-form events first (reCAPTCHA and others); a reported error ends it before any directory call
        if (await LoggingInAsync(typed) is { } refused)
        {
            (refusal.Reason, refusal.Count) = (refused, true);
            return null;
        }

        // (b) Tor's throttle, the bind as the user and the group gate
        if (_throttle.IsBlocked(userKey, client))
        {
            refusal.Reason = "rate limited";
            return null;
        }

        if (account is null)
        {
            (refusal.Reason, refusal.Count) = ("not a valid domain username", true);
            return null;
        }

        var result = _directory.Authenticate(account, password);
        if (result.Outcome != DirectoryOutcome.Success)
        {
            // a domain outage is not the user's fault: don't count it against them
            (refusal.Reason, refusal.Count) = (Describe(result.Outcome), result.Outcome != DirectoryOutcome.Unavailable);
            return null;
        }

        var (user, reason) = await _sync.SyncAsync(result);
        if (user is null)
        {
            (refusal.Reason, refusal.Count) = (reason ?? "refused", true);
            return null;
        }

        refusal.User = user;

        // (c) Orchard's own checks on the user, as after a good password in Orchard's login
        if (await StandingCheckAsync(user) is { } check)
        {
            (refusal.Reason, refusal.Count) = (check, true);
            return null;
        }

        // (d) two-factor: not supported for directory sign-in, so refused (fail closed), never skipped
        if (await _orchard.IsTwoFactorEnabledAsync(user) || await _orchard.IsTwoFactorRequiredAsync(user))
        {
            (refusal.Reason, refusal.Count) = ("two-factor account: not supported for directory sign-in", true);
            return null;
        }

        // e.g. the directory snapshot (Tor Account); a failure there must not block the sign-in
        foreach (var handler in _signInHandlers)
        {
            try
            {
                await handler.SignedInAsync(user, result);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Tor: a sign-in handler failed ({Handler}: {Error}).", handler.GetType().Name, ex.GetType().Name);
            }
        }

        // (e) success: the cookie, then Orchard's success events once each, as Orchard's login raises them.
        // Nothing after the cookie may turn this into a failure, so those steps only log.
        await _orchard.SignInAsync(user);
        await RaiseAsync(e => e.LoggedInAsync(user), "LoggedInAsync");
        try
        {
            await _orchard.TriggerLoggedInWorkflowAsync(user);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning("Tor: the logged-in workflow event failed ({Error}).", ex.GetType().Name);
        }

        return result;
    }

    /// <summary>Raises LoggingInAsync on every subscriber; the reason when any reports an error or throws, else null.</summary>
    private async Task<string?> LoggingInAsync(string typed)
    {
        var errors = 0;
        foreach (var loginEvent in _loginEvents)
        {
            try
            {
                await loginEvent.LoggingInAsync(typed, (_, _) => errors++);
            }
            catch (Exception ex)
            {
                // Orchard's login logs and carries on here; a directory sign-in fails closed instead
                _logger.LogWarning("Tor: a login form event failed ({Handler}: {Error}).", loginEvent.GetType().Name, ex.GetType().Name);
                return "login form check failed (" + loginEvent.GetType().Name + ")";
            }
        }

        return errors > 0 ? "login form check refused" : null;
    }

    /// <summary>The checks Orchard makes on a user after the password; the reason when one fails, else null.</summary>
    private async Task<string?> StandingCheckAsync(User user)
    {
        if (!user.IsEnabled)
        {
            return "Orchard user disabled";
        }

        if (await _orchard.IsLockedOutAsync(user))
        {
            // the event Orchard raises for a locked-out user (Audit Trail "locked out")
            await RaiseAsync(e => e.IsLockedOutAsync(user), "IsLockedOutAsync");
            return "Orchard user locked out";
        }

        if (!await _orchard.CanSignInAsync(user))
        {
            return "Orchard does not allow this user to sign in (confirmation required)";
        }

        // other checks plugged into Orchard's login (email confirmation, moderation, ...): any answer refuses
        foreach (var loginEvent in _loginEvents)
        {
            if (await loginEvent.ValidatingLoginAsync(user) is not null)
            {
                return "Orchard login check refused (" + loginEvent.GetType().Name + ")";
            }
        }

        return null;
    }

    /// <summary>The one failure answer: Tor's log with the cause, Orchard's failure event once, the generic message.</summary>
    private async Task<IActionResult> FailAsync(string typed, string client, string path, string reason, User? user, string? returnUrl)
    {
        _audit.Failure(typed, client, path, reason);

        if (user is null)
        {
            var name = SignInAudit.Clean(typed);
            await RaiseAsync(e => e.LoggingInFailedAsync(name), "LoggingInFailedAsync");
        }
        else
        {
            await RaiseAsync(e => e.LoggingInFailedAsync((IUser)user), "LoggingInFailedAsync");
        }

        await _notifier.ErrorAsync(H["Invalid login attempt."]);
        var target = !string.IsNullOrEmpty(returnUrl) && IsLocalUrl(returnUrl)
            ? "~/Login?ReturnUrl=" + Uri.EscapeDataString(returnUrl)
            : "~/Login";
        return new LocalRedirectResult(target);
    }

    // each subscriber once; like Orchard's login, a failing subscriber is logged and the others still run
    private async Task RaiseAsync(Func<ILoginFormEvent, Task> raise, string eventName)
    {
        foreach (var loginEvent in _loginEvents)
        {
            try
            {
                await raise(loginEvent);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Tor: login event {Event} failed in {Handler} ({Error}).", eventName, loginEvent.GetType().Name, ex.GetType().Name);
            }
        }
    }

    private bool IsLocalAccount(string typed)
    {
        var name = typed.Trim();
        return name.Length > 0 && name.IndexOfAny(['\\', '@']) < 0 &&
            _options.LocalAccounts.Contains(name, StringComparer.OrdinalIgnoreCase);
    }

    // same rule as Url.IsLocalUrl: one leading slash, not "//" or "/\"
    internal static bool IsLocalUrl(string url) =>
        url.Length > 0 && url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\')) ||
        url.Length > 1 && url[0] == '~' && url[1] == '/';

    private static string Describe(DirectoryOutcome outcome) => outcome switch
    {
        DirectoryOutcome.BadCredentials => "bad credentials",
        DirectoryOutcome.AccountDisabled => "account disabled",
        DirectoryOutcome.AccountLocked => "account locked",
        DirectoryOutcome.AccountExpired => "account expired",
        DirectoryOutcome.PasswordExpired => "password expired",
        DirectoryOutcome.NotFound => "account not readable",
        DirectoryOutcome.Unavailable => "directory unavailable",
        _ => outcome.ToString(),
    };
}
