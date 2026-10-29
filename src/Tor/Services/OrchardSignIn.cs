// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OrchardCore.Users;
using OrchardCore.Users.Events;
using OrchardCore.Users.Models;
using OrchardCore.Workflows.Services;

namespace Tor.Services;

/// <summary>
/// Orchard's own checks and sign-in for a user Tor has matched to a directory account: the same checks
/// Orchard's password login makes after the password (lockout, CanSignIn, two-factor), and the cookie.
/// </summary>
public interface IOrchardSignIn
{
    /// <summary>Orchard's lockout (UserManager.IsLockedOutAsync).</summary>
    Task<bool> IsLockedOutAsync(User user);

    /// <summary>SignInManager.CanSignInAsync: the configured confirmed-email, confirmed-phone and confirmation rules.</summary>
    Task<bool> CanSignInAsync(User user);

    /// <summary>The user has turned on two-factor authentication in Orchard.</summary>
    Task<bool> IsTwoFactorEnabledAsync(User user);

    /// <summary>Orchard requires two-factor authentication for this user (site-wide or by role).</summary>
    Task<bool> IsTwoFactorRequiredAsync(User user);

    /// <summary>Issues the sign-in cookie (not persistent).</summary>
    Task SignInAsync(User user);

    /// <summary>Orchard's UserLoggedInEvent workflow event, as Orchard's login raises it, when Workflows is on.</summary>
    Task TriggerLoggedInWorkflowAsync(User user);
}

public sealed class OrchardSignIn : IOrchardSignIn
{
    private readonly SignInManager<IUser> _signInManager;
    private readonly UserManager<IUser> _userManager;
    private readonly IServiceProvider _services;

    public OrchardSignIn(SignInManager<IUser> signInManager, UserManager<IUser> userManager, IServiceProvider services)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _services = services;
    }

    public Task<bool> IsLockedOutAsync(User user) => _userManager.IsLockedOutAsync(user);

    public Task<bool> CanSignInAsync(User user) => _signInManager.CanSignInAsync(user);

    public Task<bool> IsTwoFactorEnabledAsync(User user) => _userManager.GetTwoFactorEnabledAsync(user);

    // the coordinator exists only while one of Orchard's two-factor features is on
    public async Task<bool> IsTwoFactorRequiredAsync(User user) =>
        _services.GetService<ITwoFactorAuthenticationHandlerCoordinator>() is { } coordinator && await coordinator.IsRequiredAsync(user);

    public Task SignInAsync(User user) => _signInManager.SignInAsync(user, isPersistent: false);

    public async Task TriggerLoggedInWorkflowAsync(User user)
    {
        if (_services.GetService<IWorkflowManager>() is not { } workflowManager)
        {
            return;
        }

        var input = new Dictionary<string, object>
        {
            ["UserName"] = user.UserName,
            ["ExternalClaims"] = Array.Empty<object>(),
            ["Roles"] = user.RoleNames,
            ["Provider"] = DirectoryUserSync.LoginProvider,
        };

        await workflowManager.TriggerEventAsync("UserLoggedInEvent", input, user.UserId);
    }
}
