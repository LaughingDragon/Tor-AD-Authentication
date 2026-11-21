// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// The fixes from the line-by-line security review of 0.1.0-preview, one section per review item.
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using OrchardCore.DisplayManagement.Notify;
using OrchardCore.Modules.Manifest;
using Tor.Controllers;
using Tor.Directory;
using Tor.Filters;
using Tor.Services;
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

    // ---- item 19: nothing from /account is stored by a browser or a proxy
    [Fact]
    public void Every_account_response_is_private_and_never_stored()
    {
        var http = new DefaultHttpContext();
        http.Response.Headers.CacheControl = "private, no-cache"; // what the picture actions set before
        var action = new ActionContext(http, new RouteData(), new ActionDescriptor());
        var context = new ResultExecutingContext(action, [], new OkResult(), new object());

        foreach (var filter in typeof(AccountController).GetCustomAttributes(inherit: true).OfType<IResultFilter>())
        {
            filter.OnResultExecuting(context);
        }

        Assert.Equal("private, no-store", http.Response.Headers.CacheControl.ToString());
    }

    // ---- item 2: the login password is bounded before the throttle and the bind
    [Fact]
    public async Task A_login_password_over_256_characters_never_reaches_the_directory_and_counts_as_a_failure()
    {
        var r = new Rig();

        var result = await r.SignInAsync(password: new string('x', 257));

        Assert.Equal(0, r.Journal.Count("bind"));
        Assert.Equal("~/Login", Assert.IsType<LocalRedirectResult>(result).Url);
        Assert.Equal([(NotifyType.Error, "Invalid login attempt.")], r.Notifier.Messages);
        Assert.Equal(1, r.Journal.Count("LoggingInFailed"));

        for (var i = 1; i < r.Options.MaxFailuresPerUser; i++)
        {
            await r.SignInAsync(password: new string('x', 1_000_000));
        }

        Assert.True(r.Throttle.IsBlocked("alice", "198.51.100.99"));
    }

    [Fact]
    public async Task A_login_password_of_256_characters_still_binds()
    {
        var r = new Rig();

        await r.SignInAsync(password: new string('x', 256));

        Assert.Equal(256, Assert.Single(r.Directory.Passwords).Length);
    }

    /// <summary>A directory sign-in with stand-ins, as in <see cref="LoginFilterTests"/>.</summary>
    private sealed class Rig
    {
        public Journal Journal { get; } = new();
        public FakeDirectory Directory { get; }
        public FakeSync Sync { get; }
        public FakeOrchard Orchard { get; }
        public RecordingLoginEvents Events { get; }
        public FakeNotifier Notifier { get; } = new();
        public ListLogger Log { get; } = new();
        public LoginThrottle Throttle { get; }
        public TorOptions Options { get; }
        public IDirectoryAuthenticator? Authenticator { get; init; }

        public Rig(TorOptions? options = null)
        {
            Options = options ?? new() { Domain = "corp.example.com", NetBiosName = "CORP", Servers = ["dc.invalid"], LocalAccounts = ["breakglass"] };
            Directory = new FakeDirectory(Journal);
            Sync = new FakeSync(Journal);
            Orchard = new FakeOrchard(Journal);
            Events = new RecordingLoginEvents(Journal);
            Throttle = new LoginThrottle(Microsoft.Extensions.Options.Options.Create(Options), TimeProvider.System);
        }

        public DirectoryLoginFilter Filter() => new(
            Microsoft.Extensions.Options.Options.Create(Options),
            Authenticator ?? Directory,
            Sync,
            Throttle,
            new SignInAudit(Log),
            Orchard,
            [Events],
            [],
            new ListLogger<DirectoryLoginFilter>(Log),
            Notifier,
            new FakeLocalizer<DirectoryLoginFilter>());

        public Task<IActionResult> SignInAsync(string userName = "alice", string password = "Pa55-word-never-logged!", string client = "192.0.2.10", string? returnUrl = null) =>
            Filter().SignInDirectoryAsync(userName, password, client, returnUrl);
    }
}
