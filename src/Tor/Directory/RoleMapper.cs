// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.Extensions.Logging;

namespace Tor.Directory;

/// <summary>The role changes for one sign-in. Only managed roles ever appear in Add or Remove.</summary>
public sealed record RoleChanges(IReadOnlyList<string> Add, IReadOnlyList<string> Remove);

/// <summary>
/// Maps AD group membership to Orchard roles, touching only the roles in the mapping. The mapping is the
/// configured GroupRoles minus what is refused here: blank entries, and entries for the Administrator role
/// unless AllowAdministratorMapping is on.
/// </summary>
public sealed class RoleMapper
{
    public const string AdministratorRole = "Administrator";

    private readonly Dictionary<string, string> _groupRoles;
    private readonly HashSet<string> _managedRoles;

    public RoleMapper(IReadOnlyDictionary<string, string> groupRoles, bool allowAdministratorMapping = false, ILogger? logger = null)
    {
        AllowAdministratorMapping = allowAdministratorMapping;
        _groupRoles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (group, role) in groupRoles)
        {
            if (string.IsNullOrWhiteSpace(group) || string.IsNullOrWhiteSpace(role))
            {
                logger?.LogWarning("Tor: a GroupRoles entry with an empty group or role is ignored.");
                continue;
            }

            if (IsAdministrator(role) && !allowAdministratorMapping)
            {
                logger?.LogWarning("Tor: GroupRoles entry {Group} -> {Role} is ignored: mapping to Administrator needs AllowAdministratorMapping.", group.Trim(), role.Trim());
                continue;
            }

            _groupRoles[group.Trim()] = role.Trim();
        }

        _managedRoles = new HashSet<string>(_groupRoles.Values, StringComparer.OrdinalIgnoreCase);

        if (allowAdministratorMapping)
        {
            logger?.LogWarning("Tor: AllowAdministratorMapping is on: a directory group can grant the Administrator role.");
        }
    }

    /// <summary>Builds the mapper from the options (logs ignored entries and the Administrator warning).</summary>
    public static RoleMapper From(TorOptions options, ILogger? logger = null) =>
        new(options.GroupRoles ?? [], options.AllowAdministratorMapping, logger);

    public bool AllowAdministratorMapping { get; }

    /// <summary>The effective mapping (group -> role), after the refused entries are removed.</summary>
    public IReadOnlyDictionary<string, string> Map => _groupRoles;

    public IEnumerable<string> ManagedGroups => _groupRoles.Keys;

    public static bool IsAdministrator(string role) => string.Equals(role.Trim(), AdministratorRole, StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the user is in at least one managed group: the sign-in gate.</summary>
    public bool IsAllowed(IEnumerable<string> groups) => groups.Any(_groupRoles.ContainsKey);

    /// <summary>The managed roles this membership grants.</summary>
    public IReadOnlySet<string> RolesFor(IEnumerable<string> groups)
    {
        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in groups)
        {
            if (_groupRoles.TryGetValue(group, out var role))
            {
                roles.Add(role);
            }
        }

        return roles;
    }

    /// <summary>What to add and remove so the user's managed roles match the groups; other roles are left alone.</summary>
    public RoleChanges Changes(IEnumerable<string> currentRoles, IEnumerable<string> groups) =>
        Changes(currentRoles, groups, grantable: null);

    /// <summary>
    /// As <see cref="Changes(IEnumerable{string}, IEnumerable{string})"/>, but only roles in <paramref name="grantable"/>
    /// (when given) are added; managed roles the user no longer qualifies for are still removed.
    /// </summary>
    public RoleChanges Changes(IEnumerable<string> currentRoles, IEnumerable<string> groups, IReadOnlySet<string>? grantable)
    {
        var wanted = RolesFor(groups);
        var current = new HashSet<string>(currentRoles, StringComparer.OrdinalIgnoreCase);

        var add = wanted.Where(r => !current.Contains(r) && (grantable is null || grantable.Contains(r))).Order(StringComparer.OrdinalIgnoreCase).ToList();
        var remove = current.Where(r => _managedRoles.Contains(r) && !wanted.Contains(r)).Order(StringComparer.OrdinalIgnoreCase).ToList();

        return new RoleChanges(add, remove);
    }
}
