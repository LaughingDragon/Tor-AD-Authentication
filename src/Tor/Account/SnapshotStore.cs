// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using OrchardCore.ContentManagement;
using OrchardCore.Users;
using OrchardCore.Users.Models;
using Tor.Directory;
using Tor.Services;

namespace Tor.Account;

/// <summary>Writes and reads the DirectoryProfile snapshot on the Orchard user (Custom User Settings).</summary>
public sealed class SnapshotStore : IDirectorySignInHandler
{
    private readonly IContentManager _contentManager;
    private readonly UserManager<IUser> _userManager;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public SnapshotStore(IContentManager contentManager, UserManager<IUser> userManager, TimeProvider time, ILogger<SnapshotStore> logger)
    {
        _contentManager = contentManager;
        _userManager = userManager;
        _time = time;
        _logger = logger;
    }

    public Task SignedInAsync(User user, DirectoryResult result) =>
        result.Snapshot is null ? Task.CompletedTask : SaveAsync(user, result.Snapshot);

    /// <summary>Replaces the whole snapshot; a value that is gone from AD is gone here too.</summary>
    public async Task SaveAsync(User user, DirectorySnapshot snapshot)
    {
        var item = await _contentManager.NewAsync(AccountMigrations.DirectoryProfileType);
        item.Alter<DirectoryProfilePart>(part => part.Apply(snapshot, _time.GetUtcNow().UtcDateTime));
        user.Properties[AccountMigrations.DirectoryProfileType] = JObject.FromObject(item);

        var saved = await _userManager.UpdateAsync(user);
        if (!saved.Succeeded)
        {
            _logger.LogWarning("Tor: the directory snapshot could not be saved on the Orchard user.");
        }
    }

    public static DirectoryProfilePart? Read(User user) =>
        user.Properties.TryGetPropertyValue(AccountMigrations.DirectoryProfileType, out var node) && node is JsonObject
            ? node.ToObject<ContentItem>() is { } item && item.TryGet<DirectoryProfilePart>(out var part) ? part : null
            : null;
}
