// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Globalization;

namespace Tor.Directory;

/// <summary>
/// The user's own directory object as read at sign-in, with the bind of that sign-in.
/// Values are capped and the domain part of mail and UPN is lower-cased; nothing here is a secret.
/// </summary>
public sealed record DirectorySnapshot
{
    public const int MaxText = 256;
    public const int MaxDescription = 1024;
    public const int MaxListItems = 50;
    public const int MaxPhotoBytes = 100 * 1024;

    public string? DisplayName { get; init; }
    public string? Mail { get; init; }
    public string? UserPrincipalName { get; init; }
    public string? Title { get; init; }
    public string? Department { get; init; }
    public string? Description { get; init; }
    public string? TelephoneNumber { get; init; }
    public string? Mobile { get; init; }
    public string? Office { get; init; }
    public DateTime? WhenCreatedUtc { get; init; }
    public DateTime? PasswordLastSetUtc { get; init; }

    /// <summary>Null when the password never expires.</summary>
    public DateTime? PasswordExpiresUtc { get; init; }

    public DateTime? LastLogonUtc { get; init; }

    /// <summary>Null when the account never expires.</summary>
    public DateTime? AccountExpiresUtc { get; init; }

    public bool Enabled { get; init; }
    public string? HomeDirectory { get; init; }
    public IReadOnlyList<string> Groups { get; init; } = [];
    public IReadOnlyList<string> ManagedComputers { get; init; } = [];

    /// <summary>thumbnailPhoto, only when it is a JPEG or PNG of at most <see cref="MaxPhotoBytes"/>.</summary>
    public byte[]? Photo { get; init; }

    public string? PhotoContentType { get; init; }

    internal static string? Cap(string? value, int max = MaxText)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim();
        return text.Length <= max ? text : text[..max];
    }

    /// <summary>"Name@Corp.Example.COM" -> "Name@corp.example.com"; the local part keeps its case.</summary>
    internal static string? LowerDomain(string? address)
    {
        var text = Cap(address);
        if (text is null)
        {
            return null;
        }

        var at = text.LastIndexOf('@');
        return at < 0 ? text : text[..at] + text[at..].ToLowerInvariant();
    }

    /// <summary>A 100 ns FILETIME as UTC; 0 and Int64.MaxValue (never / not set) give null.</summary>
    internal static DateTime? FromFileTime(string? value)
    {
        if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ticks) || ticks <= 0 || ticks == long.MaxValue)
        {
            return null;
        }

        try
        {
            return DateTime.FromFileTimeUtc(ticks);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>LDAP GeneralizedTime as AD writes it, e.g. "20261023081500.0Z".</summary>
    internal static DateTime? FromGeneralizedTime(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        return DateTime.TryParseExact(value, ["yyyyMMddHHmmss.0Z", "yyyyMMddHHmmss'Z'", "yyyyMMddHHmmss.fZ"], CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var time)
            ? DateTime.SpecifyKind(time, DateTimeKind.Utc)
            : null;
    }

    /// <summary>The image type of a JPEG or PNG by its signature, or null for anything else.</summary>
    internal static string? ImageType(ReadOnlySpan<byte> data) => data switch
    {
        [0xFF, 0xD8, 0xFF, ..] => "image/jpeg",
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, ..] => "image/png",
        _ => null,
    };

    internal static IReadOnlyList<string> CapList(IEnumerable<string?> values) =>
        values.Select(v => Cap(v)).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase).Take(MaxListItems).ToList();
}
