// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.DisplayManagement.Handlers;
using OrchardCore.DisplayManagement.Views;

namespace Tor.Account;

/// <summary>Adds the AccountContact shape (phone, mobile, location) to the Content zone, for domain accounts allowed to.</summary>
public sealed class AccountContactDisplayDriver : DisplayDriver<AccountPage>
{
    private readonly LocationChoices _locations;

    public AccountContactDisplayDriver(LocationChoices locations) => _locations = locations;

    public override IDisplayResult Display(AccountPage page, BuildDisplayContext context) =>
        Initialize<AccountContactViewModel>("AccountContact", async model =>
            {
                var options = await _locations.NamesAsync();
                model.OfficeEnabled = options.Count > 0;
                model.TelephoneNumber = page.Profile?.TelephoneNumber;
                model.Mobile = page.Profile?.Mobile;
                model.Office = page.Profile?.Office;
                model.OfficeOptions = [.. options];
                model.OfficeIsUnlisted = model.Office is { } office && !options.Contains(office, StringComparer.Ordinal);
            })
            .Location("Content:30")
            .RenderWhen(() => Task.FromResult(page.CanChangeContact && !page.IsLocal));
}
