// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Account actions: input rules, messages, the write allow-list, LDAP result mapping and the attempt limit.
// No test contacts a domain controller.
using System.DirectoryServices.Protocols;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Tor.Account;
using Tor.Directory;
using Tor.Services;
using Xunit;

namespace Tor.Tests;

public class AccountActionTests
{
    // made-up values for the input rules only; nothing here is sent anywhere
    private const string Old = "old-Value-1";
    private const string New = "new-Value-2";

    [Fact]
    public void Password_input_rules()
    {
        Assert.Null(AccountActions.ValidatePassword(Old, New, New));
        Assert.NotNull(AccountActions.ValidatePassword("", New, New));
        Assert.NotNull(AccountActions.ValidatePassword(Old, "", ""));
        Assert.NotNull(AccountActions.ValidatePassword(Old, New, New + "x"));
        Assert.NotNull(AccountActions.ValidatePassword(Old, Old, Old));
        Assert.NotNull(AccountActions.ValidatePassword(Old, "a\u0001b", "a\u0001b"));
        var tooLong = new string('x', AccountActions.MaxPasswordLength + 1);
        Assert.NotNull(AccountActions.ValidatePassword(Old, tooLong, tooLong));
        Assert.NotNull(AccountActions.ValidatePassword(tooLong, New, New));
    }

    [Fact]
    public void Messages_never_contain_what_was_typed()
    {
        var typed = new[] { Old, New, New + "x", "a\u0001b" };
        foreach (var (current, next, confirm) in new[] { ("", New, New), (Old, New, New + "x"), (Old, Old, Old), (Old, "a\u0001b", "a\u0001b") })
        {
            var message = AccountActions.ValidatePassword(current, next, confirm)!;
            Assert.DoesNotContain(typed, t => message.Contains(t, StringComparison.Ordinal));
        }

        foreach (var outcome in Enum.GetValues<DirectoryWriteOutcome>())
        {
            Assert.DoesNotContain(typed, t => AccountActions.PasswordMessage(outcome).Contains(t, StringComparison.Ordinal));
            Assert.DoesNotContain(typed, t => AccountActions.AuditOutcome(outcome).Contains(t, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Password_value_is_quoted_utf16()
    {
        Assert.Equal(Encoding.Unicode.GetBytes("\"" + New + "\""), DirectoryAuthenticator.PasswordValue(New));
    }

    [Theory]
    [InlineData(ResultCode.ConstraintViolation, DirectoryWriteOutcome.PolicyViolation)]
    [InlineData(ResultCode.InsufficientAccessRights, DirectoryWriteOutcome.NotAllowed)]
    [InlineData(ResultCode.Unavailable, DirectoryWriteOutcome.Unavailable)]
    [InlineData(ResultCode.Busy, DirectoryWriteOutcome.Unavailable)]
    [InlineData(ResultCode.UnwillingToPerform, DirectoryWriteOutcome.Refused)]
    [InlineData(ResultCode.NoSuchObject, DirectoryWriteOutcome.Refused)]
    public void Write_failures(ResultCode code, DirectoryWriteOutcome expected) =>
        Assert.Equal(expected, DirectoryAuthenticator.ClassifyWriteFailure(code));

    [Fact]
    public void Only_allow_listed_attributes_are_written()
    {
        Assert.Equal(["mobile", "physicalDeliveryOfficeName", "telephoneNumber", "thumbnailPhoto"], DirectoryAuthenticator.WritableAttributes.Order(StringComparer.Ordinal));

        // refused before any connection is made
        var writer = Writer(useLdaps: true);
        var account = AccountName.Parse("someone", "CORP", "corp.example.com")!;
        foreach (var name in new[] { "memberOf", "userAccountControl", "unicodePwd", "mail", "displayName", "telephoneNumber;binary" })
        {
            Assert.Equal(DirectoryWriteOutcome.Refused, writer.Replace(account, "S-1-5-21-1-2-3-1000", Old, new Dictionary<string, object?> { [name] = "x" }).Outcome);
        }

        Assert.Equal(DirectoryWriteOutcome.Refused, writer.Replace(account, "S-1-5-21-1-2-3-1000", Old, new Dictionary<string, object?>()).Outcome);
        Assert.Equal(DirectoryWriteOutcome.Refused, writer.Replace(account, "S-1-5-21-1-2-3-1000", Old, new Dictionary<string, object?> { ["mobile"] = 42 }).Outcome);
    }

    [Fact]
    public void Password_change_needs_ldaps()
    {
        var account = AccountName.Parse("someone", "CORP", "corp.example.com")!;
        Assert.Equal(DirectoryWriteOutcome.NotSecure, Writer(useLdaps: false).ChangePassword(account, "S-1-5-21-1-2-3-1000", Old, New).Outcome);
    }

    [Fact]
    public void Three_attempts_per_window_per_key()
    {
        var time = new ManualTime();
        var limiter = new ActionLimiter(time);
        var window = TimeSpan.FromMinutes(15);

        Assert.True(limiter.TryAcquire("password:u1", 3, window));
        Assert.True(limiter.TryAcquire("password:u1", 3, window));
        Assert.True(limiter.TryAcquire("password:u1", 3, window));
        Assert.False(limiter.TryAcquire("password:u1", 3, window));

        // another user, or another action, has its own count
        Assert.True(limiter.TryAcquire("password:u2", 3, window));
        Assert.True(limiter.TryAcquire("picture:u1", 3, window));

        time.Advance(TimeSpan.FromMinutes(14));
        Assert.False(limiter.TryAcquire("password:u1", 3, window));
        time.Advance(TimeSpan.FromMinutes(1));
        Assert.True(limiter.TryAcquire("password:u1", 3, window));
    }

    private static DirectoryAuthenticator Writer(bool useLdaps) => new(
        Options.Create(new TorOptions { Domain = "corp.example.com", NetBiosName = "CORP", Servers = ["dc.invalid"], UseLdaps = useLdaps }),
        NullLogger<DirectoryAuthenticator>.Instance);

    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 26, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
