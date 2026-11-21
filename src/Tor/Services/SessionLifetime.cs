// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Tor.Services;

/// <summary>
/// An absolute lifetime for Orchard's sign-in cookie, for every sign-in while Tor is on: a session ends
/// <see cref="TorOptions.MaxSessionHours"/> after the sign-in that started it, however often it is used. The sliding
/// expiry renews the cookie and moves its IssuedUtc, so the start is kept in the cookie's own properties.
/// </summary>
public static class SessionLifetime
{
    public const string StartedKey = "Tor.SessionStarted";
    public const int MaxHours = 720;

    public static TimeSpan Length(TorOptions options) => TimeSpan.FromHours(Math.Clamp(options.MaxSessionHours, 1, MaxHours));

    /// <summary>Adds the lifetime to the cookie's events, before whatever validation is already there (the security stamp).</summary>
    public static void Apply(CookieAuthenticationOptions cookie, TorOptions options, TimeProvider time)
    {
        var signingIn = cookie.Events.OnSigningIn;
        cookie.Events.OnSigningIn = context =>
        {
            // a new sign-in starts a session; a refreshed one (same properties) keeps its start
            context.Properties.Items.TryAdd(StartedKey, time.GetUtcNow().ToString("O", CultureInfo.InvariantCulture));
            return signingIn(context);
        };

        var validate = cookie.Events.OnValidatePrincipal;
        cookie.Events.OnValidatePrincipal = async context =>
        {
            var now = time.GetUtcNow();

            // a cookie from before this version has no start: it counts from when it was issued
            var started = Started(context.Properties) ?? context.Properties.IssuedUtc;
            if (started is null || now - started.Value >= Length(options))
            {
                context.RejectPrincipal();
                await context.HttpContext.SignOutAsync(context.Scheme.Name);
                return;
            }

            if (!context.Properties.Items.ContainsKey(StartedKey))
            {
                context.Properties.Items[StartedKey] = started.Value.ToString("O", CultureInfo.InvariantCulture);
                context.ShouldRenew = true;
            }

            await validate(context);
        };
    }

    private static DateTimeOffset? Started(AuthenticationProperties properties) =>
        properties.Items.TryGetValue(StartedKey, out var text) &&
        DateTimeOffset.TryParseExact(text, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var started)
            ? started
            : null;
}
