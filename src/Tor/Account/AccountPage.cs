// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.Users.Models;

namespace Tor.Account;

/// <summary>
/// The model behind /account. Display drivers turn it into the AccountPage shape and the shapes in its zones.
/// It always describes the signed-in user; nothing in a request can point it at someone else.
/// </summary>
public sealed class AccountPage
{
    public required User User { get; init; }

    /// <summary>True for an Orchard account with no directory link (the break-glass admin).</summary>
    public required bool IsLocal { get; init; }

    public DirectoryProfilePart? Profile { get; init; }

    /// <summary>The account actions this user may use (permission, and a directory link for the domain ones).</summary>
    public bool CanChangePassword { get; init; }

    public bool CanChangePicture { get; init; }

    public bool CanChangeContact { get; init; }

    /// <summary>Every account may have a site picture (local accounts too), given ChangeOwnSitePicture.</summary>
    public bool CanChangeSitePicture { get; init; }

    /// <summary>Public address of the site picture in the Media library, or null.</summary>
    public string? SitePictureUrl { get; init; }
}

/// <summary>Model of the AccountSitePicture shape: upload or remove the picture shown on this site. Field name: Picture (file).</summary>
public class AccountSitePictureViewModel
{
    public string ActionUrl { get; set; } = AccountActions.SitePicturePath;
    public string RemoveUrl { get; set; } = AccountActions.SitePicturePath + "/remove";
    public long MaxBytes { get; set; } = PictureProcessor.MaxUploadBytes;
    public string Accept { get; set; } = "image/jpeg,image/png";
    public int Size { get; set; } = SitePictureStore.Size;

    /// <summary>The current site picture (Media library address), or null.</summary>
    public string? PictureUrl { get; set; }

    public bool IsLocal { get; set; }
}

/// <summary>
/// Model of the AccountContact shape: the contact details form. Field names: CurrentPassword, TelephoneNumber,
/// Mobile, Office. Office is a choice from OfficeOptions (or empty); a current value not in the list is kept as an extra choice.
/// </summary>
public class AccountContactViewModel
{
    public string ActionUrl { get; set; } = AccountActions.ContactPath;
    public int MaxPhoneLength { get; set; } = AccountActions.MaxPhoneLength;
    public int MaxPasswordLength { get; set; } = AccountActions.MaxPasswordLength;
    public string? TelephoneNumber { get; set; }
    public string? Mobile { get; set; }
    public string? Office { get; set; }

    /// <summary>False when no Location choices are configured: the form has no Location field.</summary>
    public bool OfficeEnabled { get; set; }

    /// <summary>The configured Location choices, sorted.</summary>
    public string[] OfficeOptions { get; set; } = [];

    /// <summary>True when Office is set but is not one of OfficeOptions (show it as the selected extra choice).</summary>
    public bool OfficeIsUnlisted { get; set; }
}

/// <summary>Model of the AccountPicture shape: the domain picture upload form. Field names: CurrentPassword, Picture (file).</summary>
public class AccountPictureViewModel
{
    public string ActionUrl { get; set; } = AccountActions.PicturePath;
    public long MaxBytes { get; set; } = PictureProcessor.MaxUploadBytes;
    public string Accept { get; set; } = "image/jpeg,image/png";
    public int MaxPasswordLength { get; set; } = AccountActions.MaxPasswordLength;

    /// <summary>The current domain picture (/account/picture), or null when there is none.</summary>
    public string? PhotoUrl { get; set; }
}

/// <summary>Model of the AccountPassword shape: the change-password form. Field names: CurrentPassword, NewPassword, ConfirmPassword.</summary>
public class AccountPasswordViewModel
{
    public string ActionUrl { get; set; } = AccountActions.PasswordPath;
    public int MaxLength { get; set; } = AccountActions.MaxPasswordLength;
    public DateTime? PasswordLastSetUtc { get; set; }
    public DateTime? PasswordExpiresUtc { get; set; }
    public bool PasswordNeverExpires { get; set; }
}

/// <summary>Model of the AccountProfile shape: the snapshot as of the last sign-in.</summary>
public class AccountProfileViewModel
{
    public string UserName { get; set; } = "";
    public bool IsLocal { get; set; }
    public bool HasSnapshot { get; set; }
    public DateTime? SyncedUtc { get; set; }
    public string? DisplayName { get; set; }
    public string? Mail { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? Title { get; set; }
    public string? Department { get; set; }
    public string? Description { get; set; }
    public string? TelephoneNumber { get; set; }
    public string? Mobile { get; set; }
    public string? Office { get; set; }
    public DateTime? WhenCreatedUtc { get; set; }
    public DateTime? PasswordLastSetUtc { get; set; }
    public DateTime? PasswordExpiresUtc { get; set; }
    public bool PasswordNeverExpires { get; set; }
    public DateTime? LastLogonUtc { get; set; }
    public DateTime? AccountExpiresUtc { get; set; }
    public bool AccountNeverExpires { get; set; }
    public bool Enabled { get; set; }
    public string? HomeDirectory { get; set; }
    public string[] Groups { get; set; } = [];
    public string[] ManagedComputers { get; set; } = [];

    /// <summary>Same-origin address of the domain picture (/account/picture), or null when there is none.</summary>
    public string? PhotoUrl { get; set; }

    /// <summary>The site picture (Media library address), or null. For local accounts the only picture.</summary>
    public string? SitePictureUrl { get; set; }
}
