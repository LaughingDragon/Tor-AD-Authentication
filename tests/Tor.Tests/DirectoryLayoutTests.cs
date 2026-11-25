// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Directory layouts other than a flat one, as far as they can be checked without a domain: nested groups, long group
// lists, and the group-list cap of the snapshot (display only, never the gate). These use stand-in SIDs; a real
// directory with these layouts is covered by DomainIntegrationTests only when its test accounts are set up.
using Tor.Directory;
using Xunit;

namespace Tor.Tests;

public class DirectoryLayoutTests
{
    private const string Domain = "S-1-5-21-1000000000-2000000000-3000000000";

    private static string GroupSid(int rid) => $"{Domain}-{rid}";

    private static RoleMapper Mapper(params (string Group, string Role)[] entries) =>
        RoleMapper.From(new TorOptions { GroupRoles = entries.ToDictionary(e => e.Group, e => e.Role, StringComparer.OrdinalIgnoreCase) });

    [Fact]
    public void Nested_group_counts_through_the_token()
    {
        // the user is a direct member of Team-A only; Team-A is a member of Web-Members. AD puts both SIDs in tokenGroups.
        var token = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { GroupSid(513), GroupSid(5001), GroupSid(6001) };
        var managed = new (string?, string?)[] { ("Web-Members", GroupSid(6001)) };

        Assert.Equal(["Web-Members"], DirectoryAuthenticator.MemberOf(token, managed));
    }

    [Fact]
    public void Managed_group_outside_the_token_does_not_count()
    {
        var token = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { GroupSid(513), GroupSid(5001) };
        var managed = new (string?, string?)[] { ("Web-Members", GroupSid(6001)), ("Web-Guests", GroupSid(6002)) };

        Assert.Empty(DirectoryAuthenticator.MemberOf(token, managed));
    }

    [Fact]
    public void Long_token_finds_the_managed_groups_wherever_they_are()
    {
        // 3,000 groups in the token, the managed ones at the start, the middle and the end
        var token = new HashSet<string>(Enumerable.Range(10_000, 3_000).Select(GroupSid), StringComparer.OrdinalIgnoreCase);
        var managed = new (string?, string?)[]
        {
            ("Web-First", GroupSid(10_000)), ("Web-Middle", GroupSid(11_500)), ("Web-Last", GroupSid(12_999)), ("Web-None", GroupSid(99_999)),
        };

        Assert.Equal(["Web-First", "Web-Middle", "Web-Last"], DirectoryAuthenticator.MemberOf(token, managed));
    }

    [Fact]
    public void A_group_without_a_name_or_sid_is_ignored()
    {
        var token = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { GroupSid(6001) };
        var managed = new (string?, string?)[] { (null, GroupSid(6001)), ("Web-Members", null) };

        Assert.Empty(DirectoryAuthenticator.MemberOf(token, managed));
    }

    [Fact]
    public void More_managed_groups_than_the_snapshot_shows_still_all_map()
    {
        // 60 mapped groups: the snapshot shows 50, but every one of the 60 grants its role
        var entries = Enumerable.Range(1, 60).Select(i => ($"Web-Team-{i:00}", $"Team {i:00}")).ToArray();
        var mapper = Mapper(entries);
        var token = new HashSet<string>(Enumerable.Range(1, 60).Select(i => GroupSid(7000 + i)), StringComparer.OrdinalIgnoreCase);
        var managed = entries.Select((e, i) => ((string?)e.Item1, (string?)GroupSid(7001 + i)));

        var groups = DirectoryAuthenticator.MemberOf(token, managed);

        Assert.Equal(60, groups.Count);
        Assert.Equal(60, mapper.RolesFor(groups).Count);
        Assert.Equal(DirectorySnapshot.MaxListItems, DirectorySnapshot.CapList(groups).Count);
    }

    [Fact]
    public void Group_names_match_whatever_their_case()
    {
        var mapper = Mapper(("Web-Members", "Members"));

        Assert.Equal(["Members"], mapper.RolesFor(["WEB-MEMBERS"]));
    }
}
