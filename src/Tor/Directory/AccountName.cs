// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
namespace Tor.Directory;

public enum AccountNameKind
{
    // "name"
    Plain,

    // "DOMAIN\name"
    DownLevel,

    // "name@suffix"
    UserPrincipalName,
}

/// <summary>A domain username as typed on the login form: name, DOMAIN\name or a UPN.</summary>
public sealed record AccountName(AccountNameKind Kind, string Name, string? UpnSuffix)
{
    private const int MaxSamAccountName = 20;
    private const int MaxUpn = 256;

    // characters AD does not allow in a sAMAccountName (plus the separators handled below)
    private static readonly char[] _forbidden = ['"', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>'];

    /// <summary>The login name to bind with: UPN as typed, otherwise just the name (domain is set separately).</summary>
    public string BindName => Kind == AccountNameKind.UserPrincipalName ? $"{Name}@{UpnSuffix}" : Name;

    /// <summary>Key for rate limiting: the same person typed three ways is still one key when the suffix is the domain.</summary>
    public string ThrottleKey => Kind == AccountNameKind.UserPrincipalName ? BindName.ToLowerInvariant() : Name.ToLowerInvariant();

    /// <summary>
    /// Parses what the user typed. A DOMAIN\ prefix must name this domain (NetBIOS or DNS name).
    /// Returns null for anything that cannot be a valid account of this domain.
    /// </summary>
    public static AccountName? Parse(string? input, string netBiosName, string dnsDomain)
    {
        var text = input?.Trim();
        if (string.IsNullOrEmpty(text) || text.Length > MaxUpn || text.Any(char.IsControl))
        {
            return null;
        }

        var slash = text.IndexOf('\\');
        var at = text.IndexOf('@');

        if (slash >= 0)
        {
            if (at >= 0 || text.IndexOf('\\', slash + 1) >= 0)
            {
                return null;
            }

            var domain = text[..slash];
            if (!domain.Equals(netBiosName, StringComparison.OrdinalIgnoreCase) &&
                !domain.Equals(dnsDomain, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var name = text[(slash + 1)..];
            return IsSamAccountName(name) ? new AccountName(AccountNameKind.DownLevel, name, null) : null;
        }

        if (at >= 0)
        {
            if (text.IndexOf('@', at + 1) >= 0)
            {
                return null;
            }

            var name = text[..at];
            var suffix = text[(at + 1)..];
            if (name.Length == 0 || suffix.Length == 0 || name.IndexOfAny(_forbidden) >= 0 || suffix.IndexOfAny(_forbidden) >= 0 ||
                suffix.Any(char.IsWhiteSpace) || suffix.StartsWith('.') || suffix.EndsWith('.'))
            {
                return null;
            }

            return new AccountName(AccountNameKind.UserPrincipalName, name, suffix);
        }

        return IsSamAccountName(text) ? new AccountName(AccountNameKind.Plain, text, null) : null;
    }

    private static bool IsSamAccountName(string name) =>
        name.Length is > 0 and <= MaxSamAccountName &&
        name.IndexOfAny(_forbidden) < 0 &&
        !name.EndsWith('.') &&
        name.Trim().Length == name.Length;
}
