// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.Extensions.Logging;
using OrchardCore.Modules;
using Tor.Directory;

namespace Tor.Services;

/// <summary>
/// At tenant start: builds the role mapping (which logs refused entries and the Administrator warning) and
/// writes the effective mapping, group and role names only, to Tor's audit log.
/// </summary>
public sealed class RoleMappingLog : ModularTenantEvents
{
    private readonly RoleMapper _roleMapper;
    private readonly ILogger _audit;

    public RoleMappingLog(RoleMapper roleMapper, ILoggerFactory loggerFactory)
    {
        _roleMapper = roleMapper;
        _audit = loggerFactory.CreateLogger(SignInAudit.LoggerName);
    }

    public override Task ActivatedAsync()
    {
        var entries = string.Join(", ", _roleMapper.Map.OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase).Select(e => $"{e.Key} -> {e.Value}"));
        _audit.LogInformation(
            "Role mapping loaded: {Count} entries ({Entries}); AllowAdministratorMapping={Allow}",
            _roleMapper.Map.Count, entries.Length == 0 ? "none" : entries, _roleMapper.AllowAdministratorMapping);

        if (_roleMapper.Map.Count == 0)
        {
            _audit.LogWarning("Role mapping is empty: no directory account can sign in until GroupRoles is configured.");
        }

        return Task.CompletedTask;
    }
}
