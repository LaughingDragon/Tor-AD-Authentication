// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Name parsing for the login form.
using Tor.Directory;
using Xunit;

namespace Tor.Tests;

public class AccountNameTests
{
    private const string NetBios = "CORP";
    private const string Dns = "corp.example.com";

    private static AccountName? Parse(string? input) => AccountName.Parse(input, NetBios, Dns);

    [Theory]
    [InlineData("alice", AccountNameKind.Plain, "alice", null)]
    [InlineData("  alice  ", AccountNameKind.Plain, "alice", null)]
    [InlineData(@"CORP\alice", AccountNameKind.DownLevel, "alice", null)]
    [InlineData(@"corp\alice", AccountNameKind.DownLevel, "alice", null)]
    [InlineData(@"corp.example.com\alice", AccountNameKind.DownLevel, "alice", null)]
    [InlineData("alice@corp.example.com", AccountNameKind.UserPrincipalName, "alice", "corp.example.com")]
    [InlineData("alice.smith@example.com", AccountNameKind.UserPrincipalName, "alice.smith", "example.com")]
    [InlineData("a.b-c_d", AccountNameKind.Plain, "a.b-c_d", null)]
    [InlineData("al(ce)", AccountNameKind.Plain, "al(ce)", null)]
    public void Accepts_the_three_forms(string input, AccountNameKind kind, string name, string? suffix)
    {
        var account = Parse(input);

        Assert.NotNull(account);
        Assert.Equal(kind, account.Kind);
        Assert.Equal(name, account.Name);
        Assert.Equal(suffix, account.UpnSuffix);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"OTHER\alice")]
    [InlineData(@"\alice")]
    [InlineData(@"CORP\")]
    [InlineData(@"CORP\a\b")]
    [InlineData(@"CORP\alice@corp.example.com")]
    [InlineData("alice@")]
    [InlineData("@corp.example.com")]
    [InlineData("a@b@c")]
    [InlineData("alice@.example.com")]
    [InlineData("alice@example.com.")]
    [InlineData("alice@exa mple.com")]
    [InlineData("al*ce")]
    [InlineData("alice=1")]
    [InlineData("a,b")]
    [InlineData("alice.")]
    [InlineData("twentyonecharacters!x")]
    [InlineData("ali\u0000ce")]
    [InlineData("ali\nce")]
    public void Refuses_anything_else(string? input)
    {
        Assert.Null(Parse(input));
    }

    [Fact]
    public void Refuses_overlong_input()
    {
        Assert.Null(Parse(new string('a', 100) + "@" + new string('b', 200) + ".org"));
    }

    [Fact]
    public void Bind_name_is_the_upn_or_the_bare_name()
    {
        Assert.Equal("alice@corp.example.com", Parse("alice@corp.example.com")!.BindName);
        Assert.Equal("alice", Parse(@"CORP\alice")!.BindName);
        Assert.Equal("alice", Parse("alice")!.BindName);
    }

    [Fact]
    public void Plain_and_down_level_share_a_throttle_key()
    {
        Assert.Equal(Parse("Alice")!.ThrottleKey, Parse(@"corp\ALICE")!.ThrottleKey);
    }
}
