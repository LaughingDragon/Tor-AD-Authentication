// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.Security.Permissions;

namespace Tor.Account;

/// <summary>
/// Account permissions. Each one only ever acts on the signed-in user. ManageOwnAccount implies all of them.
/// Default grants (applied by Orchard when the feature is first enabled, to roles of these names):
/// Intranet Users get ManageOwnAccount; Guests get viewing, their domain password and the site picture.
/// </summary>
public sealed class AccountPermissions : IPermissionProvider
{
    public const string IntranetUsersRole = "Intranet Users";
    public const string GuestsRole = "Guests";

    public static readonly Permission ManageOwnAccount = new("ManageOwnAccount", "Manage own account (all account actions)");
    public static readonly Permission ViewOwnAccount = new("ViewOwnAccount", "View own account page", [ManageOwnAccount]);
    public static readonly Permission ChangeOwnDomainPassword = new("ChangeOwnDomainPassword", "Change own domain password", [ManageOwnAccount]);
    public static readonly Permission ChangeOwnDomainPicture = new("ChangeOwnDomainPicture", "Change own domain picture", [ManageOwnAccount]);
    public static readonly Permission ChangeOwnContactDetails = new("ChangeOwnContactDetails", "Change own domain contact details", [ManageOwnAccount]);
    public static readonly Permission ChangeOwnSitePicture = new("ChangeOwnSitePicture", "Change own site profile picture", [ManageOwnAccount]);

    private static readonly IEnumerable<Permission> _all =
    [
        ManageOwnAccount, ViewOwnAccount, ChangeOwnDomainPassword, ChangeOwnDomainPicture, ChangeOwnContactDetails, ChangeOwnSitePicture,
    ];

    private static readonly IEnumerable<Permission> _guests = [ViewOwnAccount, ChangeOwnDomainPassword, ChangeOwnSitePicture];

    public Task<IEnumerable<Permission>> GetPermissionsAsync() => Task.FromResult(_all);

    public IEnumerable<PermissionStereotype> GetDefaultStereotypes() =>
    [
        new PermissionStereotype { Name = "Administrator", Permissions = _all },
        new PermissionStereotype { Name = IntranetUsersRole, Permissions = [ManageOwnAccount] },
        new PermissionStereotype { Name = GuestsRole, Permissions = _guests },
    ];
}
