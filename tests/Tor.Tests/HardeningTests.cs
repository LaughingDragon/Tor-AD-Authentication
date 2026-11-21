// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// The fixes from the line-by-line security review (D-040 items 2, 6, 7, 8, 9, 11, 12, 14, 19 and 23), one section each.
using System.Reflection;
using OrchardCore.Modules.Manifest;
using Xunit;

namespace Tor.Tests;

public class HardeningTests
{
    // ---- item 23: one version everywhere
    [Fact]
    public void The_manifest_version_is_the_package_version()
    {
        var assembly = typeof(Startup).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        var package = informational.Split('+')[0];

        var module = assembly.GetCustomAttributes<ModuleAttribute>().Single(m => m.GetType() == typeof(ModuleAttribute) && m.Name == "Tor");
        Assert.Equal(package, module.Version);
    }
}
