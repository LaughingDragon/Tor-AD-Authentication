// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Reflection;
using OrchardCore.Modules;
using ManifestFeature = OrchardCore.Modules.Manifest.FeatureAttribute;
using ModuleManifest = OrchardCore.Modules.Manifest.ModuleAttribute;
using TypeFeature = OrchardCore.Modules.FeatureAttribute;
using Xunit;

namespace Tor.Tests;

// The module declares its features explicitly, so each startup must name the feature it belongs to, and "Tor" must
// exist for Tor.Account to depend on (R-040 item 20, D-042 stage 6).
public sealed class FeatureTests
{
    private static readonly Assembly _tor = typeof(Startup).Assembly;

    private static ManifestFeature[] DeclaredFeatures() =>
        [.. _tor.GetCustomAttributes<ManifestFeature>().Where(f => f is not ModuleManifest)];

    [Fact]
    public void The_Tor_feature_is_declared_and_Tor_Account_depends_on_it()
    {
        var features = DeclaredFeatures();

        var tor = Assert.Single(features, f => f.Id == "Tor");
        Assert.Contains("OrchardCore.Users", tor.Dependencies);
        Assert.Contains("OrchardCore.Roles", tor.Dependencies);
        Assert.Contains("Tor", Assert.Single(features, f => f.Id == "Tor.Account").Dependencies);
    }

    [Fact]
    public void Every_startup_names_a_declared_feature_and_sign_in_belongs_to_Tor()
    {
        var ids = DeclaredFeatures().Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
        var startups = _tor.GetTypes().Where(t => typeof(IStartup).IsAssignableFrom(t) && !t.IsAbstract).ToList();

        Assert.NotEmpty(startups);
        foreach (var startup in startups)
        {
            var feature = startup.GetCustomAttribute<TypeFeature>();
            Assert.True(feature is not null, $"{startup.FullName} has no [Feature]");
            Assert.Contains(feature!.FeatureName, ids);
        }

        Assert.Equal("Tor", typeof(Startup).GetCustomAttribute<TypeFeature>()!.FeatureName);
        Assert.Equal("Tor.Account", typeof(AccountStartup).GetCustomAttribute<TypeFeature>()!.FeatureName);
    }
}
