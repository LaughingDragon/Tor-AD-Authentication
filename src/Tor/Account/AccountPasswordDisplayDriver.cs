// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.DisplayManagement.Handlers;
using OrchardCore.DisplayManagement.Views;

namespace Tor.Account;

/// <summary>Adds the AccountPassword shape (change domain password) to the Content zone, for domain accounts allowed to.</summary>
public sealed class AccountPasswordDisplayDriver : DisplayDriver<AccountPage>
{
    public override IDisplayResult Display(AccountPage page, BuildDisplayContext context) =>
        Initialize<AccountPasswordViewModel>("AccountPassword", model =>
            {
                model.PasswordLastSetUtc = page.Profile?.PasswordLastSetUtc;
                model.PasswordExpiresUtc = page.Profile?.PasswordExpiresUtc;
                model.PasswordNeverExpires = page.Profile is { } profile && profile.PasswordExpiresUtc is null;
            })
            .Location("Content:10")
            .RenderWhen(() => Task.FromResult(page.CanChangePassword && !page.IsLocal));
}
