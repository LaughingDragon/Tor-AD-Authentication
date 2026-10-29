// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using OrchardCore.Security.Services;
using OrchardCore.Users;
using OrchardCore.Users.Models;
using OrchardCore.Users.Services;
using Tor.Directory;

namespace Tor.Services;

/// <summary>Creates or matches the Orchard user for an AD account and sets its managed roles.</summary>
public interface IDirectoryUserSync
{
    /// <summary>The Orchard user to sign in, or null with the reason (for the audit log only).</summary>
    Task<(User? User, string? Reason)> SyncAsync(DirectoryResult account);
}

/// <summary>Creates or matches the Orchard user for an AD account (keyed by SID) and sets its managed roles.</summary>
public sealed class DirectoryUserSync : IDirectoryUserSync
{
    public const string LoginProvider = "Tor";
    public const string DisplayNameClaim = "tor:display_name";

    private readonly UserManager<IUser> _userManager;
    private readonly IUserService _userService;
    private readonly RoleMapper _roleMapper;
    private readonly IRoleService _roleService;
    private readonly ILogger _logger;

    public DirectoryUserSync(UserManager<IUser> userManager, IUserService userService, RoleMapper roleMapper, IRoleService roleService, ILogger<DirectoryUserSync> logger)
    {
        _userManager = userManager;
        _userService = userService;
        _roleMapper = roleMapper;
        _roleService = roleService;
        _logger = logger;
    }

    /// <summary>The Orchard user to sign in, or null with the reason (for the audit log only).</summary>
    public async Task<(User? User, string? Reason)> SyncAsync(DirectoryResult account)
    {
        var groups = account.Groups ?? [];
        if (!_roleMapper.IsAllowed(groups))
        {
            return (null, "not in a managed group");
        }

        // a mapped role that does not exist, or the admin role without the flag, is never granted
        var grantable = await GrantableAsync(_roleMapper.RolesFor(groups));
        if (grantable.Count == 0)
        {
            return (null, "no mapped role can be granted");
        }

        var user = await _userManager.FindByLoginAsync(LoginProvider, account.Sid!) as User;
        if (user is null)
        {
            (user, var reason) = await CreateAsync(account);
            if (user is null)
            {
                return (null, reason);
            }
        }
        else if (!user.IsEnabled)
        {
            return (null, "Orchard user disabled");
        }

        await UpdateDetailsAsync(user, account);
        await ApplyRolesAsync(user, groups, grantable);

        return (user, null);
    }

    private async Task<IReadOnlySet<string>> GrantableAsync(IReadOnlySet<string> wanted)
    {
        var existing = new HashSet<string>(await _roleService.GetNormalizedRoleNamesAsync(), StringComparer.OrdinalIgnoreCase);
        var grantable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var role in wanted)
        {
            if (!existing.Contains(role))
            {
                _logger.LogWarning("Tor: mapped role {Role} does not exist in Orchard and is ignored.", role);
                continue;
            }

            // Orchard's admin role may be renamed: ask Orchard, not only the name
            if (!_roleMapper.AllowAdministratorMapping && await _roleService.IsAdminRoleAsync(role))
            {
                _logger.LogWarning("Tor: mapped role {Role} is Orchard's admin role and is ignored: AllowAdministratorMapping is off.", role);
                continue;
            }

            grantable.Add(role);
        }

        return grantable;
    }

    private async Task<(User? User, string? Reason)> CreateAsync(DirectoryResult account)
    {
        var userName = account.SamAccountName!;

        // never take over a local account that happens to have the same name
        if (await _userManager.FindByNameAsync(userName) is not null)
        {
            return (null, "username belongs to an unlinked Orchard user");
        }

        var user = new User
        {
            UserName = userName,
            Email = EmailOf(account),
            EmailConfirmed = true,
            IsEnabled = true,
        };

        string? error = null;
        // the local password is random and never shown: AD-linked users always sign in through Tor
        var created = await _userService.CreateUserAsync(user, RandomPassword(), (_, message) => error ??= message);
        if (created is not User saved)
        {
            _logger.LogWarning("Tor: could not create the Orchard user ({Error}).", error);
            return (null, "Orchard user could not be created");
        }

        var linked = await _userManager.AddLoginAsync(saved, new UserLoginInfo(LoginProvider, account.Sid!, "Active Directory"));
        if (!linked.Succeeded)
        {
            return (null, "SID could not be stored");
        }

        return (saved, null);
    }

    private async Task UpdateDetailsAsync(User user, DirectoryResult account)
    {
        var email = EmailOf(account);
        if (!string.Equals(user.Email, email, StringComparison.OrdinalIgnoreCase))
        {
            var changed = await _userManager.SetEmailAsync(user, email);
            if (!changed.Succeeded)
            {
                _logger.LogWarning("Tor: email from AD not applied for an Orchard user (already in use or invalid).");
            }
        }

        var claims = await _userManager.GetClaimsAsync(user);
        var current = claims.FirstOrDefault(c => c.Type == DisplayNameClaim);
        var displayName = account.DisplayName ?? account.SamAccountName!;
        if (current is null)
        {
            await _userManager.AddClaimAsync(user, new Claim(DisplayNameClaim, displayName));
        }
        else if (current.Value != displayName)
        {
            await _userManager.ReplaceClaimAsync(user, current, new Claim(DisplayNameClaim, displayName));
        }
    }

    private async Task ApplyRolesAsync(User user, IReadOnlyList<string> groups, IReadOnlySet<string> grantable)
    {
        var changes = _roleMapper.Changes(await _userManager.GetRolesAsync(user), groups, grantable);
        if (changes.Remove.Count > 0)
        {
            await _userManager.RemoveFromRolesAsync(user, changes.Remove);
        }

        if (changes.Add.Count > 0)
        {
            await _userManager.AddToRolesAsync(user, changes.Add);
        }
    }

    // Orchard needs an email; an account without mail gets its UPN, which has the same shape
    private static string EmailOf(DirectoryResult account) =>
        account.Mail ?? account.UserPrincipalName ?? $"{account.SamAccountName}@invalid";

    // 48 random characters from all four classes, so any password policy accepts it
    internal static string RandomPassword()
    {
        const string lower = "abcdefghijkmnopqrstuvwxyz", upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", digits = "23456789", symbols = "!#$%&*+-=?@^_~";
        const string all = lower + upper + digits + symbols;
        var chars = new char[48];
        chars[0] = lower[RandomNumberGenerator.GetInt32(lower.Length)];
        chars[1] = upper[RandomNumberGenerator.GetInt32(upper.Length)];
        chars[2] = digits[RandomNumberGenerator.GetInt32(digits.Length)];
        chars[3] = symbols[RandomNumberGenerator.GetInt32(symbols.Length)];
        for (var i = 4; i < chars.Length; i++)
        {
            chars[i] = all[RandomNumberGenerator.GetInt32(all.Length)];
        }

        RandomNumberGenerator.Shuffle(chars.AsSpan());
        return new string(chars);
    }
}
