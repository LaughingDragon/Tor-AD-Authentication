// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// SIDs, LDAP escaping, bind errors, expiry, throttling and the other small rules.
using System.DirectoryServices.Protocols;
using Microsoft.Extensions.Options;
using Tor.Directory;
using Tor.Filters;
using Tor.Services;
using Xunit;

namespace Tor.Tests;

public class HelperTests
{
    [Fact]
    public void Sid_well_known_and_domain()
    {
        // S-1-5-32-544 (Administrators)
        Assert.Equal("S-1-5-32-544", Sid.ToText([1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0]));
        // S-1-5-21-1-2-3-1104
        Assert.Equal("S-1-5-21-1-2-3-1104", Sid.ToText([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x50, 0x04, 0, 0]));
    }

    [Fact]
    public void Sid_refuses_malformed_bytes()
    {
        Assert.Null(Sid.ToText([]));
        Assert.Null(Sid.ToText([2, 1, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0]));
        Assert.Null(Sid.ToText([1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0]));
    }

    [Theory]
    [InlineData("alice", "alice")]
    [InlineData("a*", @"a\2a")]
    [InlineData("(x)", @"\28x\29")]
    [InlineData(@"a\b", @"a\5cb")]
    [InlineData("a\0", @"a\00")]
    public void Ldap_filter_values_are_escaped(string value, string escaped)
    {
        Assert.Equal(escaped, DirectoryAuthenticator.Escape(value));
    }

    [Theory]
    [InlineData("80090308: LdapErr: DSID-0C09050F, comment: AcceptSecurityContext error, data 52e, v4563", DirectoryOutcome.BadCredentials)]
    [InlineData("... data 533, v4563", DirectoryOutcome.AccountDisabled)]
    [InlineData("... data 775, v4563", DirectoryOutcome.AccountLocked)]
    [InlineData("... data 701, v4563", DirectoryOutcome.AccountExpired)]
    [InlineData("... data 532, v4563", DirectoryOutcome.PasswordExpired)]
    [InlineData("... data 773, v4563", DirectoryOutcome.PasswordExpired)]
    [InlineData(null, DirectoryOutcome.BadCredentials)]
    public void Bind_failures_are_classified(string? serverMessage, DirectoryOutcome outcome)
    {
        Assert.Equal(outcome, DirectoryAuthenticator.ClassifyBindFailure(new LdapException(49, "invalid credentials", serverMessage)));
    }

    [Fact]
    public void Server_down_is_unavailable_not_a_bad_password()
    {
        Assert.Equal(DirectoryOutcome.Unavailable, DirectoryAuthenticator.ClassifyBindFailure(new LdapException(81, "server down")));
    }

    [Fact]
    public void Account_expiry()
    {
        var now = new DateTimeOffset(2026, 10, 25, 0, 0, 0, TimeSpan.Zero);

        Assert.False(DirectoryAuthenticator.IsExpired(null, now));
        Assert.False(DirectoryAuthenticator.IsExpired("0", now));
        Assert.False(DirectoryAuthenticator.IsExpired(long.MaxValue.ToString(), now));
        Assert.True(DirectoryAuthenticator.IsExpired(now.AddDays(-1).ToFileTime().ToString(), now));
        Assert.False(DirectoryAuthenticator.IsExpired(now.AddDays(1).ToFileTime().ToString(), now));
    }

    [Fact]
    public void Throttle_blocks_a_username_after_the_limit_and_forgets_after_the_window()
    {
        var time = new ManualTime();
        var throttle = new LoginThrottle(Options.Create(new TorOptions { MaxFailuresPerUser = 3, MaxFailuresPerClient = 100 }), time);

        for (var i = 0; i < 3; i++)
        {
            Assert.False(throttle.IsBlocked("alice", "192.0.2.1"));
            throttle.RecordFailure("alice", "192.0.2.1");
        }

        Assert.True(throttle.IsBlocked("alice", "192.0.2.2"));
        Assert.False(throttle.IsBlocked("bob", "192.0.2.2"));

        time.Advance(TimeSpan.FromMinutes(15));
        Assert.False(throttle.IsBlocked("alice", "192.0.2.1"));
    }

    [Fact]
    public void Throttle_blocks_a_client_across_usernames()
    {
        var throttle = new LoginThrottle(Options.Create(new TorOptions { MaxFailuresPerUser = 100, MaxFailuresPerClient = 3 }), new ManualTime());

        throttle.RecordFailure("a", "192.0.2.1");
        throttle.RecordFailure("b", "192.0.2.1");
        throttle.RecordFailure("c", "192.0.2.1");

        Assert.True(throttle.IsBlocked("d", "192.0.2.1"));
        Assert.False(throttle.IsBlocked("d", "192.0.2.2"));
    }

    [Fact]
    public void Success_clears_the_username_only()
    {
        var throttle = new LoginThrottle(Options.Create(new TorOptions { MaxFailuresPerUser = 2, MaxFailuresPerClient = 2 }), new ManualTime());

        throttle.RecordFailure("alice", "192.0.2.1");
        throttle.RecordFailure("alice", "192.0.2.1");
        throttle.RecordSuccess("alice");

        Assert.True(throttle.IsBlocked("alice", "192.0.2.1"));
        Assert.False(throttle.IsBlocked("alice", "192.0.2.2"));
    }

    [Fact]
    public void Random_password_is_long_mixed_and_different_each_time()
    {
        var a = DirectoryUserSync.RandomPassword();
        var b = DirectoryUserSync.RandomPassword();

        Assert.Equal(48, a.Length);
        Assert.Contains(a, char.IsLower);
        Assert.Contains(a, char.IsUpper);
        Assert.Contains(a, char.IsDigit);
        Assert.Contains(a, ch => !char.IsLetterOrDigit(ch));
        Assert.NotEqual(a, b);
    }

    [Theory]
    [InlineData("alice", "alice")]
    [InlineData("al\r\nINFO forged", "alINFO forged")]
    [InlineData("  x  ", "x")]
    public void Audit_names_cannot_forge_log_lines(string typed, string logged)
    {
        Assert.Equal(logged, SignInAudit.Clean(typed));
    }

    [Theory]
    [InlineData("/", true)]
    [InlineData("/docs", true)]
    [InlineData("~/docs", true)]
    [InlineData("//evil.example", false)]
    [InlineData(@"/\evil.example", false)]
    [InlineData("https://evil.example/", false)]
    [InlineData("docs", false)]
    public void Only_local_return_urls(string url, bool local)
    {
        Assert.Equal(local, DirectoryLoginFilter.IsLocalUrl(url));
    }

    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 25, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
