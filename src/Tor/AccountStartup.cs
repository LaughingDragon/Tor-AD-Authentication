// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Fluid;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OrchardCore.ContentManagement;
using OrchardCore.Data.Migration;
using OrchardCore.DisplayManagement;
using OrchardCore.DisplayManagement.Handlers;
using OrchardCore.Modules;
using OrchardCore.Security.Permissions;
using Tor.Account;
using Tor.Services;

namespace Tor;

// Tor Account: the signed-in user's own account page.
[Feature("Tor.Account")]
public sealed class AccountStartup : StartupBase
{
    public override void ConfigureServices(IServiceCollection services)
    {
        services.AddContentPart<DirectoryProfilePart>();
        services.AddDataMigration<AccountMigrations>();
        services.AddScoped<IPermissionProvider, AccountPermissions>();

        services.AddScoped<SnapshotStore>();
        services.AddScoped<IDirectorySignInHandler>(sp => sp.GetRequiredService<SnapshotStore>());

        services.AddScoped<IDisplayDriver<AccountPage>, AccountProfileDisplayDriver>();
        services.AddScoped<IDisplayDriver<AccountPage>, AccountPasswordDisplayDriver>();
        services.AddScoped<IDisplayDriver<AccountPage>, AccountPictureDisplayDriver>();
        services.AddScoped<IDisplayDriver<AccountPage>, AccountContactDisplayDriver>();
        services.AddScoped<IDisplayDriver<AccountPage>, AccountSitePictureDisplayDriver>();
        services.AddScoped<SitePictureStore>();
        services.TryAddScoped<IAccountActionRecorder, NoAccountActionRecorder>();
        services.AddScoped<LocationChoices>();
        services.AddSingleton<ActionLimiter>();

        // the shape models a Liquid theme can read
        services.Configure<TemplateOptions>(o =>
        {
            o.MemberAccessStrategy.Register<AccountProfileViewModel>();
            o.MemberAccessStrategy.Register<AccountPasswordViewModel>();
            o.MemberAccessStrategy.Register<AccountPictureViewModel>();
            o.MemberAccessStrategy.Register<AccountContactViewModel>();
            o.MemberAccessStrategy.Register<AccountSitePictureViewModel>();
        });
    }
}
