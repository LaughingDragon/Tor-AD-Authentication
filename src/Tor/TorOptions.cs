// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
namespace Tor;

// Bound from the tenant configuration section "Tor" (appsettings of the site; nothing here names a host).
public sealed class TorOptions
{
    /// <summary>DNS name of the domain, e.g. "corp.example.com".</summary>
    public string Domain { get; set; } = "";

    /// <summary>NetBIOS name of the domain, e.g. "CORP".</summary>
    public string NetBiosName { get; set; } = "";

    /// <summary>Domain controller host names. They must match the names on the LDAPS certificates.</summary>
    public string[] Servers { get; set; } = [];

    /// <summary>LDAPS on 636. When false: LDAP on 389 with Negotiate signing and sealing.</summary>
    public bool UseLdaps { get; set; } = true;

    public int TimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// AD group (sAMAccountName) -> Orchard role. Only these roles are ever added or removed. Empty by default:
    /// with no entries nobody can sign in through the directory. Configuration binding adds to this map.
    /// </summary>
    public Dictionary<string, string> GroupRoles { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether a GroupRoles entry may grant the Administrator role. Off by default: such entries are ignored.</summary>
    public bool AllowAdministratorMapping { get; set; }

    /// <summary>Local Orchard accounts that keep the normal password login (break-glass).</summary>
    public string[] LocalAccounts { get; set; } = [];

    /// <summary>Failed sign-ins allowed per username, and per client address, in each window.</summary>
    public int MaxFailuresPerUser { get; set; } = 5;

    public int MaxFailuresPerClient { get; set; } = 20;

    public int FailureWindowMinutes { get; set; } = 15;

    /// <summary>
    /// Fixed Location (physicalDeliveryOfficeName) choices on the account page. Optional: with no choices here and
    /// no <see cref="OfficeContentType"/>, the page offers no Location field and never writes the attribute.
    /// </summary>
    public string[] OfficeChoices { get; set; } = [];

    /// <summary>Optional: a content type whose published titles are added to the Location choices.</summary>
    public string OfficeContentType { get; set; } = "";

    /// <summary>Optional, with <see cref="OfficeContentType"/>: only items whose address is under this path are offered.</summary>
    public string OfficePathPrefix { get; set; } = "";
}
