// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.DisplayManagement.Handlers;
using OrchardCore.DisplayManagement.Views;

namespace Tor.Account;

/// <summary>Adds the AccountSitePicture shape (the picture on this site) to the Content zone, for every account allowed to.</summary>
public sealed class AccountSitePictureDisplayDriver : DisplayDriver<AccountPage>
{
    public override IDisplayResult Display(AccountPage page, BuildDisplayContext context) =>
        Initialize<AccountSitePictureViewModel>("AccountSitePicture", model =>
            {
                model.PictureUrl = page.SitePictureUrl;
                model.IsLocal = page.IsLocal;
            })
            .Location("Content:40")
            .RenderWhen(() => Task.FromResult(page.CanChangeSitePicture));
}
