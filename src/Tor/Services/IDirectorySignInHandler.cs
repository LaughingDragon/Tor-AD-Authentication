// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using OrchardCore.Users.Models;
using Tor.Directory;

namespace Tor.Services;

/// <summary>Runs after a successful directory sign-in, before the cookie is issued, while the bind's data is at hand.</summary>
public interface IDirectorySignInHandler
{
    Task SignedInAsync(User user, DirectoryResult result);
}
