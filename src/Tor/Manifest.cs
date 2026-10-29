// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.Modules.Manifest;

[assembly: Module(
    Name = "Tor",
    Author = "Liam P. Ward",
    Website = "https://github.com/LaughingDragon/Tor-AD-Authentication",
    Version = "0.1.0-preview",
    Description = "Active Directory sign-in on the login page: LDAP bind as the user, group gate, managed roles.",
    Category = "Security",
    Dependencies = ["OrchardCore.Users", "OrchardCore.Roles"]
)]

[assembly: Feature(
    Id = "Tor.Account",
    Name = "Tor Account",
    Description = "The signed-in user's own account page at /account: a directory snapshot taken at sign-in, and account actions that bind as the user.",
    Category = "Security",
    Dependencies = ["Tor", "OrchardCore.Users.CustomUserSettings", "OrchardCore.Media"]
)]
