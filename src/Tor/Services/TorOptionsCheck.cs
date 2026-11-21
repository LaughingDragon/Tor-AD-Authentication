// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
namespace Tor.Services;

/// <summary>
/// What is wrong with Tor's settings, if anything. While anything is, every directory sign-in is refused (the
/// break-glass accounts still work); the problems are logged once at tenant start. Never throws, so a bad setting
/// cannot take the rest of the site down.
/// </summary>
public static class TorOptionsCheck
{
    public const int MaxTimeoutSeconds = 60;

    public static IReadOnlyList<string> Problems(TorOptions options)
    {
        var problems = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Domain))
        {
            problems.Add("Tor:Domain is empty");
        }

        if (string.IsNullOrWhiteSpace(options.NetBiosName))
        {
            problems.Add("Tor:NetBiosName is empty");
        }

        if (options.Servers.Length == 0 || options.Servers.Any(string.IsNullOrWhiteSpace))
        {
            problems.Add("Tor:Servers is empty or has an empty entry");
        }

        if (options.TimeoutSeconds is < 1 or > MaxTimeoutSeconds)
        {
            problems.Add($"Tor:TimeoutSeconds must be 1 to {MaxTimeoutSeconds}");
        }

        if (options.MaxFailuresPerUser < 1)
        {
            problems.Add("Tor:MaxFailuresPerUser must be at least 1");
        }

        if (options.MaxFailuresPerClient < 1)
        {
            problems.Add("Tor:MaxFailuresPerClient must be at least 1");
        }

        if (options.FailureWindowMinutes < 1)
        {
            problems.Add("Tor:FailureWindowMinutes must be at least 1");
        }

        if (options.MaxSessionHours is < 1 or > SessionLifetime.MaxHours)
        {
            problems.Add($"Tor:MaxSessionHours must be 1 to {SessionLifetime.MaxHours}");
        }

        return problems;
    }
}
