// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using OrchardCore.ContentManagement;
using OrchardCore.ContentManagement.Records;
using YesSql;

namespace Tor.Account;

/// <summary>
/// The choices for the Location (physicalDeliveryOfficeName) field: the fixed names in OfficeChoices, plus,
/// when OfficeContentType is set, the titles of that type's published content items (only those whose address
/// is under OfficePathPrefix, when that is set). With neither configured there are no choices, and the account
/// page offers no Location field and never writes the attribute.
/// </summary>
public sealed class LocationChoices
{
    private readonly ISession _session;
    private readonly TorOptions _options;
    private IReadOnlyList<string>? _names;

    public LocationChoices(ISession session, IOptions<TorOptions> options)
    {
        _session = session;
        _options = options.Value;
    }

    public async Task<IReadOnlyList<string>> NamesAsync()
    {
        if (_names is not null)
        {
            return _names;
        }

        IEnumerable<(string? Title, string? Path)> items = (_options.OfficeChoices ?? []).Select(name => ((string?)name, (string?)null));

        if (!string.IsNullOrWhiteSpace(_options.OfficeContentType))
        {
            var type = _options.OfficeContentType.Trim();
            var published = await _session.Query<ContentItem, ContentItemIndex>(x => x.ContentType == type && x.Published).ListAsync();
            var prefix = string.IsNullOrWhiteSpace(_options.OfficePathPrefix) ? "" : _options.OfficePathPrefix.Trim('/') + "/";
            items = items.Concat(Select(published.Select(item => ((string?)item.DisplayText, PathOf(item))), prefix).Select(name => ((string?)name, (string?)null)));
        }

        _names = Select(items, "");
        return _names;
    }

    /// <summary>Trimmed, distinct, sorted titles of at most MaxOfficeLength; with a prefix, only items whose path is under it.</summary>
    internal static IReadOnlyList<string> Select(IEnumerable<(string? Title, string? Path)> items, string prefix) =>
        items
            .Where(i => prefix.Length == 0 || i.Path is { } path && path.Trim('/').StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Select(i => i.Title?.Trim())
            .Where(t => !string.IsNullOrEmpty(t) && t.Length <= AccountActions.MaxOfficeLength)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.OrdinalIgnoreCase)
            .Take(200)
            .ToList()!;

    private static string? PathOf(ContentItem item) =>
        JObject.FromObject(item) is JsonObject json && json["AutoroutePart"]?["Path"] is JsonValue path && path.TryGetValue<string>(out var text)
            ? text
            : null;
}
