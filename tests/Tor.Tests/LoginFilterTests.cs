// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// The directory sign-in against Orchard's login sequence, with fakes for the directory, the Orchard user
// and Orchard's login-form events. No test contacts a domain controller.
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OrchardCore.DisplayManagement.Notify;
using Tor.Directory;
using Tor.Filters;
using Tor.Services;
using Xunit;

namespace Tor.Tests;

public class LoginFilterTests
{
    private const string Password = "Pa55-word-never-logged!";

    public enum Cause
    {
        LoginFormError,
        Throttled,
        InvalidName,
        BadCredentials,
        DirectoryUnavailable,
        NotInGroup,
        Disabled,
        LockedOut,
        NotAllowedToSignIn,
        LoginCheckRefused,
        TwoFactorEnabled,
        TwoFactorRequired,
        UnexpectedError,
    }

    private sealed class Harness
    {
        public Journal Journal { get; } = new();
        public FakeDirectory Directory { get; }
        public FakeSync Sync { get; }
        public FakeOrchard Orchard { get; }
        public RecordingLoginEvents Events { get; }
        public FakeNotifier Notifier { get; } = new();
        public ListLogger Log { get; } = new();
        public LoginThrottle Throttle { get; }
        public TorOptions Options { get; } = new() { Domain = "corp.example.com", NetBiosName = "CORP", Servers = ["dc.invalid"], LocalAccounts = ["breakglass"] };

        public Harness()
        {
            Directory = new FakeDirectory(Journal);
            Sync = new FakeSync(Journal);
            Orchard = new FakeOrchard(Journal);
            Events = new RecordingLoginEvents(Journal);
            Throttle = new LoginThrottle(Microsoft.Extensions.Options.Options.Create(Options), TimeProvider.System);
        }

        public Task<IActionResult> SignInAsync(string userName = "alice", string password = Password, string? returnUrl = null) =>
            new DirectoryLoginFilter(
                Microsoft.Extensions.Options.Options.Create(Options),
                Directory,
                Sync,
                Throttle,
                new SignInAudit(Log),
                Orchard,
                [Events],
                [],
                new ListLogger<DirectoryLoginFilter>(Log),
                Notifier,
                new FakeLocalizer<DirectoryLoginFilter>())
            .SignInDirectoryAsync(userName, password, "192.0.2.10", returnUrl);

        /// <summary>Everything a test could see: log lines, event arguments and messages to the user.</summary>
        public IEnumerable<string> AllText() =>
            Log.Messages.Concat(Events.Arguments).Concat(Notifier.Messages.Select(m => m.Message));
    }

    private static Harness Arrange(Cause cause)
    {
        var h = new Harness();
        switch (cause)
        {
            case Cause.LoginFormError: h.Events.ReportError = true; break;
            case Cause.Throttled:
                for (var i = 0; i < h.Options.MaxFailuresPerUser; i++)
                {
                    h.Throttle.RecordFailure("alice", "198.51.100.1");
                }

                break;
            case Cause.BadCredentials: h.Directory.Result = new DirectoryResult(DirectoryOutcome.BadCredentials); break;
            case Cause.DirectoryUnavailable: h.Directory.Result = new DirectoryResult(DirectoryOutcome.Unavailable); break;
            case Cause.NotInGroup: (h.Sync.User, h.Sync.Reason) = (null, "not in a managed group"); break;
            case Cause.Disabled: h.Sync.User!.IsEnabled = false; break;
            case Cause.LockedOut: h.Orchard.LockedOut = true; break;
            case Cause.NotAllowedToSignIn: h.Orchard.CanSignIn = false; break;
            case Cause.LoginCheckRefused: h.Events.RefuseValidation = true; break;
            case Cause.TwoFactorEnabled: h.Orchard.TwoFactorEnabled = true; break;
            case Cause.TwoFactorRequired: h.Orchard.TwoFactorRequired = true; break;
            case Cause.UnexpectedError: h.Sync.Throw = new InvalidOperationException("database gone"); break;
        }

        return h;
    }

    private static string SignInName(Cause cause) => cause == Cause.InvalidName ? "not/a*name" : "alice";

    public static TheoryData<Cause> Causes() => [.. Enum.GetValues<Cause>()];

    [Fact]
    public async Task Success_follows_Orchards_order_and_raises_each_success_event_once()
    {
        var h = new Harness();

        var result = await h.SignInAsync();

        Assert.Equal(["LoggingIn", "bind", "sync", "ValidatingLogin", "cookie", "LoggedIn", "workflow"], h.Journal.Entries);
        Assert.Equal("~/", Assert.IsType<LocalRedirectResult>(result).Url);
        Assert.Empty(h.Notifier.Messages);
        Assert.Equal(0, h.Journal.Count("LoggingInFailed"));
    }

    [Fact]
    public async Task Success_returns_to_a_local_address_only()
    {
        Assert.Equal("/docs", Assert.IsType<LocalRedirectResult>(await new Harness().SignInAsync(returnUrl: "/docs")).Url);
        Assert.Equal("~/", Assert.IsType<LocalRedirectResult>(await new Harness().SignInAsync(returnUrl: "https://evil.example/")).Url);
    }

    [Fact]
    public async Task Logging_in_event_comes_before_the_bind()
    {
        var h = new Harness();

        await h.SignInAsync();

        Assert.True(h.Journal.Entries.IndexOf("LoggingIn") < h.Journal.Entries.IndexOf("bind"));
    }

    [Fact]
    public async Task An_error_from_the_logging_in_event_makes_no_directory_call()
    {
        var h = Arrange(Cause.LoginFormError);

        await h.SignInAsync();

        Assert.Equal(0, h.Journal.Count("bind"));
        Assert.Empty(h.Directory.Passwords);
        Assert.Equal(0, h.Journal.Count("sync"));
        Assert.Equal(1, h.Journal.Count("LoggingInFailed"));
    }

    [Theory]
    [MemberData(nameof(Causes))]
    public async Task Every_failure_raises_the_failure_event_once_and_issues_no_cookie(Cause cause)
    {
        var h = Arrange(cause);

        await h.SignInAsync(SignInName(cause));

        Assert.Equal(1, h.Journal.Count("LoggingInFailed"));
        Assert.Equal(0, h.Journal.Count("LoggedIn"));
        Assert.Equal(0, h.Journal.Count("cookie"));
        Assert.Equal(0, h.Journal.Count("workflow"));
    }

    [Theory]
    [MemberData(nameof(Causes))]
    public async Task Every_failure_gives_the_same_answer(Cause cause)
    {
        var h = Arrange(cause);

        var result = await h.SignInAsync(SignInName(cause), returnUrl: "/docs");

        Assert.Equal("~/Login?ReturnUrl=%2Fdocs", Assert.IsType<LocalRedirectResult>(result).Url);
        Assert.Equal([(NotifyType.Error, "Invalid login attempt.")], h.Notifier.Messages);
    }

    [Fact]
    public async Task The_answers_for_all_causes_are_identical()
    {
        var answers = new HashSet<string>();
        foreach (var cause in Enum.GetValues<Cause>())
        {
            var h = Arrange(cause);
            var result = Assert.IsType<LocalRedirectResult>(await h.SignInAsync(SignInName(cause)));
            answers.Add(result.Url + "|" + result.Permanent + "|" + result.PreserveMethod + "|" + string.Join(";", h.Notifier.Messages));
        }

        Assert.Single(answers);
    }

    [Theory]
    [MemberData(nameof(Causes))]
    public async Task No_log_line_or_event_ever_holds_the_password(Cause cause)
    {
        var h = Arrange(cause);

        await h.SignInAsync(SignInName(cause));

        Assert.NotEmpty(h.Log.Messages);
        Assert.All(h.AllText(), text => Assert.DoesNotContain(Password, text));
    }

    [Fact]
    public async Task No_log_line_or_event_holds_the_password_on_success()
    {
        var h = new Harness();

        await h.SignInAsync();

        Assert.All(h.AllText(), text => Assert.DoesNotContain(Password, text));
    }

    [Fact]
    public async Task The_cause_goes_to_Tors_log_only()
    {
        var h = Arrange(Cause.TwoFactorEnabled);

        await h.SignInAsync();

        Assert.Contains(h.Log.Messages, m => m.Contains("two-factor", StringComparison.Ordinal));
        Assert.DoesNotContain(h.Notifier.Messages, m => m.Message.Contains("two-factor", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(Cause.TwoFactorEnabled)]
    [InlineData(Cause.TwoFactorRequired)]
    public async Task Two_factor_accounts_are_refused_after_a_good_password_and_get_no_cookie(Cause cause)
    {
        var h = Arrange(cause);

        var result = await h.SignInAsync();

        Assert.Equal(1, h.Journal.Count("bind"));
        Assert.Equal(0, h.Journal.Count("cookie"));
        Assert.Equal("~/Login", Assert.IsType<LocalRedirectResult>(result).Url);
    }

    [Theory]
    [InlineData(Cause.Disabled)]
    [InlineData(Cause.LockedOut)]
    [InlineData(Cause.NotAllowedToSignIn)]
    [InlineData(Cause.LoginCheckRefused)]
    public async Task Orchards_checks_on_the_user_refuse_the_sign_in(Cause cause)
    {
        var h = Arrange(cause);

        await h.SignInAsync();

        Assert.Equal(0, h.Journal.Count("cookie"));
        Assert.Equal(1, h.Journal.Count("LoggingInFailed"));
    }

    [Fact]
    public async Task A_locked_out_user_also_raises_Orchards_locked_out_event_once()
    {
        var h = Arrange(Cause.LockedOut);

        await h.SignInAsync();

        Assert.Equal(1, h.Journal.Count("IsLockedOut"));
    }

    [Fact]
    public async Task A_disabled_user_is_refused_before_Orchards_login_checks_run()
    {
        // Orchard's disabled-user check sets a message for the next page; it must never get the chance
        var h = Arrange(Cause.Disabled);

        await h.SignInAsync();

        Assert.Equal(0, h.Journal.Count("ValidatingLogin"));
    }

    [Fact]
    public async Task Throttling_still_stops_directory_calls()
    {
        var h = Arrange(Cause.BadCredentials);

        for (var i = 0; i < h.Options.MaxFailuresPerUser + 2; i++)
        {
            await h.SignInAsync();
        }

        Assert.Equal(h.Options.MaxFailuresPerUser, h.Journal.Count("bind"));
        Assert.Equal(h.Options.MaxFailuresPerUser + 2, h.Journal.Count("LoggingInFailed"));
    }

    [Fact]
    public async Task A_directory_outage_does_not_count_against_the_user()
    {
        var h = Arrange(Cause.DirectoryUnavailable);

        for (var i = 0; i < h.Options.MaxFailuresPerUser + 2; i++)
        {
            await h.SignInAsync();
        }

        Assert.Equal(h.Options.MaxFailuresPerUser + 2, h.Journal.Count("bind"));
    }

    [Fact]
    public async Task A_good_sign_in_clears_the_user_name_count()
    {
        var h = new Harness();
        for (var i = 0; i < h.Options.MaxFailuresPerUser - 1; i++)
        {
            h.Throttle.RecordFailure("alice", "198.51.100.1");
        }

        await h.SignInAsync();

        Assert.False(h.Throttle.IsBlocked("alice", "198.51.100.2"));
    }

    [Fact]
    public async Task The_failure_event_gets_the_typed_name_cleaned_and_never_the_password()
    {
        var h = Arrange(Cause.BadCredentials);

        await h.SignInAsync("alice\r\nforged line");

        Assert.Contains("aliceforged line", h.Events.Arguments);
    }
}
