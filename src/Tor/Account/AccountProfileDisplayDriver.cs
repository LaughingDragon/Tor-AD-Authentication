// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Tor.Directory;
using OrchardCore.DisplayManagement.Handlers;
using OrchardCore.DisplayManagement.Views;

namespace Tor.Account;

/// <summary>Adds the AccountProfile shape (the snapshot) to the Content zone of the AccountPage shape.</summary>
public sealed class AccountProfileDisplayDriver : DisplayDriver<AccountPage>
{
    public override IDisplayResult Display(AccountPage page, BuildDisplayContext context) =>
        Initialize<AccountProfileViewModel>("AccountProfile", model => Fill(model, page))
            .Location("Content:1");

    internal static void Fill(AccountProfileViewModel model, AccountPage page)
    {
        model.UserName = page.User.UserName;
        model.SitePictureUrl = page.SitePictureUrl;
        model.IsLocal = page.IsLocal;

        var profile = page.IsLocal ? null : page.Profile;
        if (profile is null)
        {
            return;
        }

        model.HasSnapshot = true;
        model.SyncedUtc = profile.SyncedUtc;
        model.DisplayName = profile.DisplayName;
        model.Mail = profile.Mail;
        model.UserPrincipalName = profile.UserPrincipalName;
        model.Title = profile.Title;
        model.Department = profile.Department;
        model.Description = profile.Description;
        model.TelephoneNumber = profile.TelephoneNumber;
        model.Mobile = profile.Mobile;
        model.Office = profile.Office;
        model.WhenCreatedUtc = profile.WhenCreatedUtc;
        model.PasswordLastSetUtc = profile.PasswordLastSetUtc;
        model.PasswordExpiresUtc = profile.PasswordExpiresUtc;
        model.PasswordNeverExpires = profile.PasswordExpiresUtc is null;
        model.LastLogonUtc = profile.LastLogonUtc;
        model.AccountExpiresUtc = profile.AccountExpiresUtc;
        model.AccountNeverExpires = profile.AccountExpiresUtc is null;
        model.Enabled = profile.Enabled;
        model.HomeDirectory = profile.HomeDirectory;
        model.Groups = profile.Groups;
        model.ManagedComputers = profile.ManagedComputers;
        model.PhotoUrl = PhotoOf(profile) is null ? null : PhotoPath;
    }

    public const string PhotoPath = "/account/picture";

    /// <summary>The stored domain picture and its type, only if it is a JPEG or PNG.</summary>
    internal static (byte[] Bytes, string ContentType)? PhotoOf(DirectoryProfilePart profile)
    {
        if (profile.Photo is not { Length: > 0 } text || profile.PhotoContentType is not ("image/jpeg" or "image/png"))
        {
            return null;
        }

        var bytes = new byte[text.Length];
        if (!Convert.TryFromBase64String(text, bytes, out var length) || length > DirectorySnapshot.MaxPhotoBytes)
        {
            return null;
        }

        bytes = bytes[..length];
        return DirectorySnapshot.ImageType(bytes) == profile.PhotoContentType ? (bytes, profile.PhotoContentType) : null;
    }
}
