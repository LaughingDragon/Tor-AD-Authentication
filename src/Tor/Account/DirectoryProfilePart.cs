// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.ContentManagement;
using Tor.Directory;

namespace Tor.Account;

/// <summary>
/// The directory snapshot, stored on the Orchard user as the Custom User Settings type DirectoryProfile.
/// Only Tor writes it (at sign-in and after an account action); it has no editor, so nobody edits it.
/// </summary>
public sealed class DirectoryProfilePart : ContentPart
{
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
    public DateTime? LastLogonUtc { get; set; }
    public DateTime? AccountExpiresUtc { get; set; }
    public bool Enabled { get; set; }
    public string? HomeDirectory { get; set; }
    public string[] Groups { get; set; } = [];
    public string[] ManagedComputers { get; set; } = [];

    /// <summary>thumbnailPhoto as base64, at most 100 KB before encoding.</summary>
    public string? Photo { get; set; }

    public string? PhotoContentType { get; set; }

    internal void Apply(DirectorySnapshot snapshot, DateTime syncedUtc)
    {
        SyncedUtc = syncedUtc;
        DisplayName = snapshot.DisplayName;
        Mail = snapshot.Mail;
        UserPrincipalName = snapshot.UserPrincipalName;
        Title = snapshot.Title;
        Department = snapshot.Department;
        Description = snapshot.Description;
        TelephoneNumber = snapshot.TelephoneNumber;
        Mobile = snapshot.Mobile;
        Office = snapshot.Office;
        WhenCreatedUtc = snapshot.WhenCreatedUtc;
        PasswordLastSetUtc = snapshot.PasswordLastSetUtc;
        PasswordExpiresUtc = snapshot.PasswordExpiresUtc;
        LastLogonUtc = snapshot.LastLogonUtc;
        AccountExpiresUtc = snapshot.AccountExpiresUtc;
        Enabled = snapshot.Enabled;
        HomeDirectory = snapshot.HomeDirectory;
        Groups = [.. snapshot.Groups];
        ManagedComputers = [.. snapshot.ManagedComputers];
        Photo = snapshot.Photo is null ? null : Convert.ToBase64String(snapshot.Photo);
        PhotoContentType = snapshot.Photo is null ? null : snapshot.PhotoContentType;
    }
}
