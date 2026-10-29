// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Test doubles for the login filter: no domain controller, no database.
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Localization;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using OrchardCore.DisplayManagement.Notify;
using OrchardCore.Users;
using OrchardCore.Users.Events;
using OrchardCore.Users.Models;
using Tor.Directory;
using Tor.Services;

namespace Tor.Tests;

/// <summary>Every log message, formatted, from every logger it creates.</summary>
internal sealed class ListLogger : ILogger, ILoggerFactory, ILoggerProvider
{
    public List<string> Messages { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        Messages.Add(formatter(state, exception));

    public ILogger CreateLogger(string categoryName) => this;

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public void Dispose()
    {
    }
}

internal sealed class ListLogger<T> : ILogger<T>
{
    private readonly ListLogger _inner;

    public ListLogger(ListLogger inner) => _inner = inner;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        _inner.Log(logLevel, eventId, state, exception, formatter);
}

/// <summary>The order things happened in, shared by the fakes of one test.</summary>
internal sealed class Journal
{
    public List<string> Entries { get; } = [];

    public int Count(string entry) => Entries.Count(e => e == entry);
}

internal sealed class FakeDirectory : IDirectoryAuthenticator
{
    private readonly Journal _journal;

    public FakeDirectory(Journal journal) => _journal = journal;

    public DirectoryResult Result { get; set; } = Success();

    public List<string> Passwords { get; } = [];

    public DirectoryResult Authenticate(AccountName account, string password)
    {
        _journal.Entries.Add("bind");
        Passwords.Add(password);
        return Result;
    }

    public static DirectoryResult Success() =>
        new(DirectoryOutcome.Success, "S-1-5-21-1-2-3-1001", "alice", "alice@corp.example.com", "Alice", "alice@corp.example.com", ["Intranet-Users"], "LDAPS 636, Negotiate");
}

internal sealed class FakeSync : IDirectoryUserSync
{
    private readonly Journal _journal;

    public FakeSync(Journal journal) => _journal = journal;

    public User? User { get; set; } = new() { UserId = "user-1", UserName = "alice", IsEnabled = true };

    public string? Reason { get; set; }

    public Exception? Throw { get; set; }

    public Task<(User? User, string? Reason)> SyncAsync(DirectoryResult account)
    {
        _journal.Entries.Add("sync");
        if (Throw is not null)
        {
            throw Throw;
        }

        return Task.FromResult((User, User is null ? Reason : null));
    }
}

internal sealed class FakeOrchard : IOrchardSignIn
{
    private readonly Journal _journal;

    public FakeOrchard(Journal journal) => _journal = journal;

    public bool LockedOut { get; set; }
    public bool CanSignIn { get; set; } = true;
    public bool TwoFactorEnabled { get; set; }
    public bool TwoFactorRequired { get; set; }

    public Task<bool> IsLockedOutAsync(User user) => Task.FromResult(LockedOut);

    public Task<bool> CanSignInAsync(User user) => Task.FromResult(CanSignIn);

    public Task<bool> IsTwoFactorEnabledAsync(User user) => Task.FromResult(TwoFactorEnabled);

    public Task<bool> IsTwoFactorRequiredAsync(User user) => Task.FromResult(TwoFactorRequired);

    public Task SignInAsync(User user)
    {
        _journal.Entries.Add("cookie");
        return Task.CompletedTask;
    }

    public Task TriggerLoggedInWorkflowAsync(User user)
    {
        _journal.Entries.Add("workflow");
        return Task.CompletedTask;
    }
}

/// <summary>An ILoginFormEvent subscriber that records every call (with its arguments) and can refuse.</summary>
internal sealed class RecordingLoginEvents : ILoginFormEvent
{
    private readonly Journal _journal;

    public RecordingLoginEvents(Journal journal) => _journal = journal;

    /// <summary>Report an error from LoggingInAsync, as reCAPTCHA does for a failed challenge.</summary>
    public bool ReportError { get; set; }

    /// <summary>Answer ValidatingLoginAsync with a result, as email confirmation does for an unconfirmed user.</summary>
    public bool RefuseValidation { get; set; }

    public List<string> Arguments { get; } = [];

    public Task LoggingInAsync(string userName, Action<string, string> reportError)
    {
        _journal.Entries.Add("LoggingIn");
        Arguments.Add(userName);
        if (ReportError)
        {
            reportError("", "The captcha was not solved.");
        }

        return Task.CompletedTask;
    }

    public Task LoggingInFailedAsync(string userName)
    {
        _journal.Entries.Add("LoggingInFailed");
        Arguments.Add(userName);
        return Task.CompletedTask;
    }

    public Task LoggingInFailedAsync(IUser user)
    {
        _journal.Entries.Add("LoggingInFailed");
        Arguments.Add(user.UserName);
        return Task.CompletedTask;
    }

    public Task IsLockedOutAsync(IUser user)
    {
        _journal.Entries.Add("IsLockedOut");
        Arguments.Add(user.UserName);
        return Task.CompletedTask;
    }

    public Task LoggedInAsync(IUser user)
    {
        _journal.Entries.Add("LoggedIn");
        Arguments.Add(user.UserName);
        return Task.CompletedTask;
    }

    public Task<IActionResult> LoggingInAsync() => Task.FromResult<IActionResult>(null!);

    public Task<IActionResult> ValidatingLoginAsync(IUser user)
    {
        _journal.Entries.Add("ValidatingLogin");
        return Task.FromResult<IActionResult>(RefuseValidation ? new RedirectResult("~/elsewhere") : null!);
    }
}

internal sealed class FakeNotifier : INotifier
{
    public List<(NotifyType Type, string Message)> Messages { get; } = [];

    public ValueTask AddAsync(NotifyType type, LocalizedHtmlString message)
    {
        Messages.Add((type, message.Value));
        return ValueTask.CompletedTask;
    }

    public IList<NotifyEntry> List() => [];
}

internal sealed class FakeLocalizer<T> : IHtmlLocalizer<T>
{
    public LocalizedHtmlString this[string name] => new(name, name);

    public LocalizedHtmlString this[string name, params object[] arguments] => new(name, string.Format(name, arguments));

    public LocalizedString GetString(string name) => new(name, name);

    public LocalizedString GetString(string name, params object[] arguments) => new(name, string.Format(name, arguments));

    public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
}
