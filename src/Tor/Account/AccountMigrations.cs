// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.Media.Settings;
using OrchardCore.ContentManagement.Metadata;
using OrchardCore.ContentManagement.Metadata.Settings;
using OrchardCore.Data.Migration;

namespace Tor.Account;

/// <summary>The Custom User Settings type that holds the directory snapshot (a code part, no fields, no editor).</summary>
public sealed class AccountMigrations : DataMigration
{
    public const string DirectoryProfileType = "DirectoryProfile";

    private readonly IContentDefinitionManager _contentDefinitionManager;

    public AccountMigrations(IContentDefinitionManager contentDefinitionManager) => _contentDefinitionManager = contentDefinitionManager;

    public async Task<int> CreateAsync()
    {
        await _contentDefinitionManager.AlterPartDefinitionAsync(nameof(DirectoryProfilePart), part => part
            .Attachable(false)
            .WithDescription("Directory details read at sign-in. Written only by Tor."));

        await _contentDefinitionManager.AlterTypeDefinitionAsync(DirectoryProfileType, type => type
            .WithDisplayName("Directory profile")
            .Stereotype("CustomUserSettings")
            .WithPart(nameof(DirectoryProfilePart)));

        return 1;
    }

    /// <summary>The site profile picture: Custom User Settings type SiteProfile with one Media field (step 5).</summary>
    public async Task<int> UpdateFrom1Async()
    {
        await _contentDefinitionManager.AlterPartDefinitionAsync(SitePictureStore.TypeName, part => part
            .Attachable(false)
            .WithDescription("The user's picture on this site. Written by the account page.")
            .WithField(SitePictureStore.FieldName, field => field
                .OfType("MediaField")
                .WithDisplayName("Picture")
                .WithSettings(new MediaFieldSettings { Multiple = false, AllowMediaText = false, AllowAnchors = false, AllowedExtensions = [".jpg"] })));

        await _contentDefinitionManager.AlterTypeDefinitionAsync(SitePictureStore.TypeName, type => type
            .WithDisplayName("Site profile")
            .Stereotype("CustomUserSettings")
            .WithPart(SitePictureStore.TypeName));

        return 2;
    }
}
