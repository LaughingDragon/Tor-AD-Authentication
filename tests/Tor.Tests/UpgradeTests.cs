// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// The 1.0 compatibility promise (docs/CONFIGURATION.md): setting keys and defaults only change in a major version.
// These tests fail if a key from 0.1.0-preview.1 stops binding, or if a default changes.
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OrchardCore.Environment.Shell.Configuration;
using Tor.Services;
using Xunit;

namespace Tor.Tests;

public class UpgradeTests
{
    // Every setting key 0.1.0-preview.1 read, with the values of its README example (example names only)
    private const string Preview1Settings = """
        {
          "OrchardCore": {
            "Tor": {
              "Domain": "corp.example.com",
              "NetBiosName": "CORP",
              "Servers": [ "dc01.corp.example.com", "dc02.corp.example.com" ],
              "UseLdaps": true,
              "TimeoutSeconds": 10,
              "GroupRoles": {
                "Web-Members": "Members",
                "Web-Guests": "Guests",
                "Web-Admins": "Administrator"
              },
              "AllowAdministratorMapping": false,
              "LocalAccounts": [ "breakglass-admin" ],
              "MaxFailuresPerUser": 5,
              "MaxFailuresPerClient": 20,
              "FailureWindowMinutes": 15,
              "MaxSessionHours": 12,
              "OfficeChoices": [ "Head Office", "North Wing" ],
              "OfficeContentType": "Office",
              "OfficePathPrefix": "/offices/"
            }
          }
        }
        """;

    private static IConfiguration Site(string json) =>
        new ConfigurationBuilder().AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json))).Build();

    // the way Orchard hands a tenant its configuration: the OrchardCore section, through Tor's own Startup
    private static TorOptions Load(string json)
    {
        var services = new ServiceCollection();
        services.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton(TimeProvider.System);
        new Startup(new ShellConfiguration(Site(json).GetSection("OrchardCore"))).ConfigureServices(services);
        return services.BuildServiceProvider().GetRequiredService<IOptions<TorOptions>>().Value;
    }

    [Fact]
    public void Preview1_settings_load_unchanged()
    {
        var options = Load(Preview1Settings);

        Assert.Equal("corp.example.com", options.Domain);
        Assert.Equal("CORP", options.NetBiosName);
        Assert.Equal(["dc01.corp.example.com", "dc02.corp.example.com"], options.Servers);
        Assert.True(options.UseLdaps);
        Assert.Equal(10, options.TimeoutSeconds);
        Assert.Equal(3, options.GroupRoles.Count);
        Assert.Equal("Members", options.GroupRoles["web-members"]);
        Assert.Equal("Guests", options.GroupRoles["Web-Guests"]);
        Assert.Equal("Administrator", options.GroupRoles["Web-Admins"]);
        Assert.False(options.AllowAdministratorMapping);
        Assert.Equal(["breakglass-admin"], options.LocalAccounts);
        Assert.Equal(5, options.MaxFailuresPerUser);
        Assert.Equal(20, options.MaxFailuresPerClient);
        Assert.Equal(15, options.FailureWindowMinutes);
        Assert.Equal(12, options.MaxSessionHours);
        Assert.Equal(["Head Office", "North Wing"], options.OfficeChoices);
        Assert.Equal("Office", options.OfficeContentType);
        Assert.Equal("/offices/", options.OfficePathPrefix);
        Assert.Empty(TorOptionsCheck.Problems(options));
    }

    [Fact]
    public void Every_preview1_key_is_still_a_setting()
    {
        // a renamed or removed key would be silently ignored by normal binding; this binding refuses unknown keys
        var section = Site(Preview1Settings).GetSection("OrchardCore:Tor");
        var options = new TorOptions();
        section.Bind(options, binder => binder.ErrorOnUnknownConfiguration = true);
        Assert.Equal(15, section.GetChildren().Count());
    }

    [Fact]
    public void Configuration_reference_lists_every_setting()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "Tor.slnx")))
        {
            root = root.Parent;
        }

        Assert.NotNull(root);
        var reference = File.ReadAllText(Path.Combine(root.FullName, "docs", "CONFIGURATION.md"));
        foreach (var property in typeof(TorOptions).GetProperties())
        {
            Assert.Contains($"| `{property.Name}` |", reference, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Minimal_preview1_settings_keep_the_defaults()
    {
        var options = Load("""
            { "OrchardCore": { "Tor": { "Domain": "corp.example.com", "NetBiosName": "CORP", "Servers": [ "dc01.corp.example.com" ],
              "GroupRoles": { "Web-Members": "Members" } } } }
            """);

        Assert.Empty(TorOptionsCheck.Problems(options));
        AssertDefaults(options, ignoreRequired: true);
    }

    [Fact]
    public void Defaults_are_the_documented_ones()
    {
        AssertDefaults(new TorOptions(), ignoreRequired: false);
    }

    // docs/CONFIGURATION.md, "Settings": change these only in a major version
    private static void AssertDefaults(TorOptions options, bool ignoreRequired)
    {
        if (!ignoreRequired)
        {
            Assert.Equal("", options.Domain);
            Assert.Equal("", options.NetBiosName);
            Assert.Empty(options.Servers);
            Assert.Empty(options.GroupRoles);
        }

        Assert.True(options.UseLdaps);
        Assert.Equal(10, options.TimeoutSeconds);
        Assert.False(options.AllowAdministratorMapping);
        Assert.Empty(options.LocalAccounts);
        Assert.Equal(5, options.MaxFailuresPerUser);
        Assert.Equal(20, options.MaxFailuresPerClient);
        Assert.Equal(15, options.FailureWindowMinutes);
        Assert.Equal(12, options.MaxSessionHours);
        Assert.Empty(options.OfficeChoices);
        Assert.Equal("", options.OfficeContentType);
        Assert.Equal("", options.OfficePathPrefix);
        Assert.Equal(60, TorOptionsCheck.MaxTimeoutSeconds);
        Assert.Equal(720, SessionLifetime.MaxHours);
    }
}
