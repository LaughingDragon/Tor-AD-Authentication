// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OrchardCore.Environment.Shell.Configuration;
using OrchardCore.Modules;
using Tor.Directory;
using Tor.Filters;
using Tor.Services;

namespace Tor;

public sealed class Startup : StartupBase
{
    private readonly IShellConfiguration _configuration;

    public Startup(IShellConfiguration configuration) => _configuration = configuration;

    public override void ConfigureServices(IServiceCollection services)
    {
        services.Configure<TorOptions>(_configuration.GetSection("Tor"));

        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<LoginThrottle>();
        services.AddSingleton<SignInAudit>();
        services.AddSingleton<DirectoryAuthenticator>();
        services.AddSingleton<IDirectoryAuthenticator>(sp => sp.GetRequiredService<DirectoryAuthenticator>());
        services.AddSingleton<IDirectoryWriter>(sp => sp.GetRequiredService<DirectoryAuthenticator>());
        services.AddSingleton(sp => RoleMapper.From(sp.GetRequiredService<IOptions<TorOptions>>().Value, sp.GetRequiredService<ILogger<RoleMapper>>()));
        services.AddScoped<IModularTenantEvents, RoleMappingLog>();
        services.AddScoped<IDirectoryUserSync, DirectoryUserSync>();
        services.AddScoped<IOrchardSignIn, OrchardSignIn>();
        services.AddScoped<DirectoryLoginFilter>();

        services.Configure<MvcOptions>(options => options.Filters.AddService<DirectoryLoginFilter>());

        // the sign-in cookie, for every login while Tor is on: HTTPS only, no script access, 8 hours sliding
        services.PostConfigure<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme, options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = true;
        });
    }
}
