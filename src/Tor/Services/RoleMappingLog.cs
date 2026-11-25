// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OrchardCore.Modules;
using Tor.Directory;

namespace Tor.Services;

/// <summary>
/// At tenant start: checks the settings (an error for each problem, a warning when LDAPS is off), builds the role
/// mapping (which logs refused entries and the Administrator warning) and writes the effective mapping, group and
/// role names only, to Tor's audit log. It also logs how many local (break-glass) accounts are configured, never
/// their names, and warns when there are none.
/// </summary>
public sealed class RoleMappingLog : ModularTenantEvents
{
    private readonly RoleMapper _roleMapper;
    private readonly TorOptions _options;
    private readonly ILogger _audit;

    public RoleMappingLog(RoleMapper roleMapper, IOptions<TorOptions> options, ILoggerFactory loggerFactory)
    {
        _roleMapper = roleMapper;
        _options = options.Value;
        _audit = loggerFactory.CreateLogger(SignInAudit.LoggerName);
    }

    public override Task ActivatedAsync()
    {
        foreach (var problem in TorOptionsCheck.Problems(_options))
        {
            _audit.LogError("Tor configuration: {Problem}; every directory sign-in is refused until it is fixed.", problem);
        }

        if (!_options.UseLdaps)
        {
            _audit.LogWarning("Tor configuration: UseLdaps is false, so sign-in uses LDAP on port 389 (signed and sealed) and the password change is refused.");
        }

        var entries = string.Join(", ", _roleMapper.Map.OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase).Select(e => $"{e.Key} -> {e.Value}"));
        _audit.LogInformation(
            "Role mapping loaded: {Count} entries ({Entries}); AllowAdministratorMapping={Allow}",
            _roleMapper.Map.Count, entries.Length == 0 ? "none" : entries, _roleMapper.AllowAdministratorMapping);

        if (_roleMapper.Map.Count == 0)
        {
            _audit.LogWarning("Role mapping is empty: no directory account can sign in until GroupRoles is configured.");
        }

        // the count only: the names of local (break-glass) accounts are never written to a log
        var localAccounts = (_options.LocalAccounts ?? []).Count(name => !string.IsNullOrWhiteSpace(name));
        _audit.LogInformation("Local accounts configured: {Count}", localAccounts);
        if (localAccounts == 0)
        {
            _audit.LogWarning("LocalAccounts is empty: no local (break-glass) account can sign in, only directory accounts.");
        }

        return Task.CompletedTask;
    }
}
