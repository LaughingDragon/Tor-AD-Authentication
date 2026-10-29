// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.Extensions.Logging;

namespace Tor.Services;

/// <summary>
/// One log line per sign-in attempt, logger "Tor.Audit": outcome, reason, username as typed, client
/// address. The time is the log line's own. Never a password.
/// </summary>
public sealed class SignInAudit
{
    public const string LoggerName = "Tor.Audit";

    private const int MaxNameLength = 128;

    private readonly ILogger _logger;

    public SignInAudit(ILoggerFactory loggerFactory) => _logger = loggerFactory.CreateLogger(LoggerName);

    public void Success(string userName, string client, string path) =>
        _logger.LogInformation("Sign-in succeeded: user={UserName} client={Client} via={Path}", Clean(userName), client, path);

    public void Failure(string userName, string client, string path, string reason) =>
        _logger.LogWarning("Sign-in failed: user={UserName} client={Client} via={Path} reason={Reason}", Clean(userName), client, path, reason);

    /// <summary>An account action: which attributes it touched (names only, never values or passwords) and how it ended.</summary>
    public void Action(string userName, string client, string action, IEnumerable<string> attributes, string outcome)
    {
        var names = string.Join(",", attributes.Select(Clean));
        if (outcome == "success")
        {
            _logger.LogInformation("Account action: user={UserName} client={Client} action={Action} attributes={Attributes} outcome={Outcome}", Clean(userName), client, action, names, outcome);
        }
        else
        {
            _logger.LogWarning("Account action: user={UserName} client={Client} action={Action} attributes={Attributes} outcome={Outcome}", Clean(userName), client, action, names, outcome);
        }
    }

    // what was typed can be anything: no control characters (no forged log lines), bounded length
    internal static string Clean(string? value)
    {
        var text = new string((value ?? "").Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        return text.Length > MaxNameLength ? text[..MaxNameLength] + "…" : text;
    }
}
