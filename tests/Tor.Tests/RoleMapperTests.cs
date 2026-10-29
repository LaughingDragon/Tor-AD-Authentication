// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Group-to-role mapping.
using Microsoft.Extensions.Configuration;
using Tor.Directory;
using Xunit;

namespace Tor.Tests;

public class RoleMapperTests
{
    // the live site's mapping, configured explicitly (with the Administrator flag on)
    private static readonly Dictionary<string, string> SiteMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Intranet-Users"] = "Intranet Users",
        ["Intranet-Admins"] = "Administrator",
        ["Intranet-Guests"] = "Guests",
    };

    private static readonly RoleMapper Mapper = new(SiteMap, allowAdministratorMapping: true);

    [Fact]
    public void Default_mapping_is_empty_and_lets_nobody_in()
    {
        var options = new TorOptions();

        Assert.Empty(options.GroupRoles);
        Assert.False(options.AllowAdministratorMapping);
        Assert.False(RoleMapper.From(options).IsAllowed(["Intranet-Users", "Intranet-Admins", "Domain Users"]));
    }

    [Theory]
    [InlineData("Administrator")]
    [InlineData("administrator")]
    [InlineData(" ADMINISTRATOR ")]
    public void Administrator_is_refused_without_the_flag(string role)
    {
        var log = new ListLogger();
        var mapper = new RoleMapper(new Dictionary<string, string> { ["Intranet-Admins"] = role, ["Intranet-Users"] = "Intranet Users" }, allowAdministratorMapping: false, log);

        Assert.False(mapper.IsAllowed(["Intranet-Admins"]));
        Assert.Empty(mapper.RolesFor(["Intranet-Admins"]));
        Assert.Equal(["Intranet-Users"], mapper.ManagedGroups);

        // the user's other roles still apply
        Assert.Equal(["Intranet Users"], mapper.RolesFor(["Intranet-Admins", "Intranet-Users"]));

        var warning = Assert.Single(log.Messages);
        Assert.Contains("Intranet-Admins", warning);
        Assert.Contains("AllowAdministratorMapping", warning);
    }

    [Fact]
    public void Administrator_is_accepted_with_the_flag_and_warned_about_once()
    {
        var log = new ListLogger();
        var mapper = new RoleMapper(SiteMap, allowAdministratorMapping: true, log);

        Assert.True(mapper.IsAllowed(["intranet-admins"]));
        Assert.Equal(["Administrator"], mapper.RolesFor(["Intranet-Admins"]));
        var warning = Assert.Single(log.Messages);
        Assert.Contains("AllowAdministratorMapping is on", warning);
    }

    [Fact]
    public void Blank_entries_are_ignored()
    {
        var mapper = new RoleMapper(new Dictionary<string, string> { [" "] = "Guests", ["Intranet-Guests"] = "" });

        Assert.Empty(mapper.Map);
    }

    [Fact]
    public void Configuration_adds_to_the_map_so_the_default_must_stay_empty()
    {
        // .NET configuration binding adds configured entries to the dictionary the options object already holds
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Tor:GroupRoles:Web-Users"] = "Intranet Users",
        }).Build();

        var options = new TorOptions();
        configuration.GetSection("Tor").Bind(options);
        Assert.Equal(["Web-Users"], options.GroupRoles.Keys);

        var prefilled = new TorOptions { GroupRoles = new(StringComparer.OrdinalIgnoreCase) { ["Old-Group"] = "Administrator" } };
        configuration.GetSection("Tor").Bind(prefilled);
        Assert.Equal(["Old-Group", "Web-Users"], prefilled.GroupRoles.Keys.Order());

        // and an Administrator entry that slips in that way is still refused without the flag
        Assert.False(RoleMapper.From(prefilled).IsAllowed(["Old-Group"]));
    }

    [Fact]
    public void The_flag_and_entries_bind_from_configuration_case_insensitively()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Tor:AllowAdministratorMapping"] = "true",
            ["Tor:GroupRoles:Intranet-Admins"] = "Administrator",
        }).Build();

        var options = new TorOptions();
        configuration.GetSection("Tor").Bind(options);

        Assert.True(RoleMapper.From(options).IsAllowed(["INTRANET-ADMINS"]));
    }

    [Fact]
    public void Roles_that_cannot_be_granted_are_not_added_but_revoked_ones_still_go()
    {
        IReadOnlySet<string> grantable = new HashSet<string>(["Intranet Users"], StringComparer.OrdinalIgnoreCase);

        var changes = Mapper.Changes(["Guests"], ["Intranet-Users", "Intranet-Admins"], grantable);

        Assert.Equal(["Intranet Users"], changes.Add);
        Assert.Equal(["Guests"], changes.Remove);
    }

    [Theory]
    [InlineData("Intranet-Users")]
    [InlineData("Intranet-Admins")]
    [InlineData("intranet-guests")]
    public void Any_managed_group_passes_the_gate(string group)
    {
        Assert.True(Mapper.IsAllowed(["Domain Users", group]));
    }

    [Fact]
    public void No_managed_group_fails_the_gate()
    {
        Assert.False(Mapper.IsAllowed([]));
        Assert.False(Mapper.IsAllowed(["Domain Users", "Domain Admins", "Intranet-Users-Old"]));
    }

    [Fact]
    public void Each_group_grants_its_role()
    {
        var roles = Mapper.RolesFor(["Intranet-Users", "Intranet-Admins", "Intranet-Guests", "Domain Admins"]);

        Assert.Equal(["Administrator", "Guests", "Intranet Users"], roles.Order());
    }

    [Fact]
    public void Adds_missing_and_removes_revoked_managed_roles()
    {
        var changes = Mapper.Changes(["Guests", "Editor"], ["Intranet-Users"]);

        Assert.Equal(["Intranet Users"], changes.Add);
        Assert.Equal(["Guests"], changes.Remove);
    }

    [Fact]
    public void Never_touches_other_roles()
    {
        var changes = Mapper.Changes(["Editor", "Contributor", "Moderator"], ["Intranet-Users"]);

        Assert.Equal(["Intranet Users"], changes.Add);
        Assert.Empty(changes.Remove);
    }

    [Fact]
    public void Leaving_every_group_removes_every_managed_role()
    {
        var changes = Mapper.Changes(["Administrator", "Intranet Users", "Guests", "Editor"], []);

        Assert.Empty(changes.Add);
        Assert.Equal(["Administrator", "Guests", "Intranet Users"], changes.Remove);
    }

    [Fact]
    public void Without_the_flag_Administrator_is_not_a_managed_role()
    {
        // the role is neither granted nor revoked by Tor: an existing Administrator assignment is left alone
        var mapper = new RoleMapper(SiteMap, allowAdministratorMapping: false);

        var changes = mapper.Changes(["Administrator", "Guests"], ["Intranet-Users"]);

        Assert.Equal(["Intranet Users"], changes.Add);
        Assert.Equal(["Guests"], changes.Remove);
    }

    [Fact]
    public void Nothing_to_do_when_roles_already_match()
    {
        var changes = Mapper.Changes(["intranet users", "Administrator"], ["Intranet-Users", "Intranet-Admins"]);

        Assert.Empty(changes.Add);
        Assert.Empty(changes.Remove);
    }
}
