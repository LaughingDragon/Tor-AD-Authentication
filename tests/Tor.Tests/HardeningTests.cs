// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// The fixes from the line-by-line security review of 0.1.0-preview, one section per review item.
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using OrchardCore.Modules.Manifest;
using Tor.Controllers;
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
}
