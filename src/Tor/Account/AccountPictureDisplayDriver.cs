// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.DisplayManagement.Handlers;
using OrchardCore.DisplayManagement.Views;

namespace Tor.Account;

/// <summary>Adds the AccountPicture shape (upload the domain picture) to the Content zone, for domain accounts allowed to.</summary>
public sealed class AccountPictureDisplayDriver : DisplayDriver<AccountPage>
{
    public override IDisplayResult Display(AccountPage page, BuildDisplayContext context) =>
        Initialize<AccountPictureViewModel>("AccountPicture", model =>
            {
                model.PhotoUrl = page.Profile is { } profile && AccountProfileDisplayDriver.PhotoOf(profile) is not null
                    ? AccountProfileDisplayDriver.PhotoPath
                    : null;
            })
            .Location("Content:20")
            .RenderWhen(() => Task.FromResult(page.CanChangePicture && !page.IsLocal));
}
