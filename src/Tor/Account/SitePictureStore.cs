// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Identity;
using OrchardCore.ContentManagement;
using OrchardCore.Media;
using OrchardCore.Media.Fields;
using OrchardCore.Users;
using OrchardCore.Users.Models;

namespace Tor.Account;

/// <summary>
/// The site profile picture: the file lives in the Media library (folder site-profile/{user}/, a random file
/// name so the address can't be guessed), and its path in the Custom User Settings type SiteProfile
/// (a Media field named Picture). Written by the server only; users get no Media permissions.
/// </summary>
public sealed class SitePictureStore
{
    public const string TypeName = "SiteProfile";
    public const string FieldName = "Picture";
    public const string Folder = "site-profile";
    public const int Size = 256;
    public const int MaxOutputBytes = 200 * 1024;

    private readonly IMediaFileStore _mediaFileStore;
    private readonly IContentManager _contentManager;
    private readonly UserManager<IUser> _userManager;

    public SitePictureStore(IMediaFileStore mediaFileStore, IContentManager contentManager, UserManager<IUser> userManager)
    {
        _mediaFileStore = mediaFileStore;
        _contentManager = contentManager;
        _userManager = userManager;
    }

    /// <summary>The Media path of the user's picture, or null.</summary>
    public static string? PathOf(User user) =>
        user.Properties.TryGetPropertyValue(TypeName, out var node) && node is JsonObject &&
        node.ToObject<ContentItem>() is { } item &&
        item.Get<ContentPart>(TypeName)?.Get<MediaField>(FieldName)?.Paths is [{ } path, ..] &&
        IsOwnPath(user, path)
            ? path
            : null;

    public string? UrlOf(User user) => PathOf(user) is { } path ? _mediaFileStore.MapPathToPublicUrl(path) : null;

    /// <summary>The bytes of the user's picture (a JPEG, as stored), or null when there is none or the file is gone.</summary>
    public async Task<byte[]?> ReadAsync(User user)
    {
        if (PathOf(user) is not { } path || await _mediaFileStore.GetFileInfoAsync(path) is not { Length: > 0 and <= MaxOutputBytes })
        {
            return null;
        }

        await using var stream = await _mediaFileStore.GetFileStreamAsync(path);
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer);
        return buffer.ToArray();
    }

    /// <summary>Stores a new picture (already checked and re-encoded) and removes the previous file.</summary>
    public async Task SaveAsync(User user, byte[] jpeg)
    {
        var previous = PathOf(user);
        var path = NewPath(user);

        using (var stream = new MemoryStream(jpeg, writable: false))
        {
            await _mediaFileStore.CreateFileFromStreamAsync(path, stream, overwrite: false);
        }

        await SetPathAsync(user, path);

        if (previous is not null)
        {
            await _mediaFileStore.TryDeleteFileAsync(previous);
        }
    }

    /// <summary>Removes the picture and its file. False when there was none.</summary>
    public async Task<bool> RemoveAsync(User user)
    {
        if (PathOf(user) is not { } previous)
        {
            return false;
        }

        await SetPathAsync(user, null);
        await _mediaFileStore.TryDeleteFileAsync(previous);
        return true;
    }

    private async Task SetPathAsync(User user, string? path)
    {
        var item = await _contentManager.NewAsync(TypeName);
        item.Alter<ContentPart>(TypeName, part => part.Alter<MediaField>(FieldName, f => f.Paths = path is null ? [] : [path]));
        user.Properties[TypeName] = JObject.FromObject(item);
        await _userManager.UpdateAsync(user);
    }

    /// <summary>site-profile/{user folder}/{32 random hex}.jpg</summary>
    internal static string NewPath(User user) =>
        $"{Folder}/{UserFolder(user)}/{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16))}.jpg";

    // the Orchard user id, letters and digits only (never the user name)
    internal static string UserFolder(User user) =>
        new string((user.UserId ?? "").Where(char.IsAsciiLetterOrDigit).ToArray()) is { Length: > 0 } id ? id : "unknown";

    // only a path in the user's own folder counts (an admin could point the field anywhere)
    internal static bool IsOwnPath(User user, string path) =>
        path.StartsWith($"{Folder}/{UserFolder(user)}/", StringComparison.Ordinal) && !path.Contains("..", StringComparison.Ordinal);
}
