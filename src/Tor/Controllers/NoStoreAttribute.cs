// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.AspNetCore.Mvc.Filters;

namespace Tor.Controllers;

/// <summary>
/// Every response of the controller, pages and pictures alike, describes one signed-in user: private to that
/// user's browser and never stored, by the browser or by a proxy. Runs after the action, so it has the last word.
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class NoStoreAttribute : ResultFilterAttribute
{
    public override void OnResultExecuting(ResultExecutingContext context) =>
        context.HttpContext.Response.Headers.CacheControl = "private, no-store";
}
