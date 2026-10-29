// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OrchardCore.AuditTrail.Services;
using OrchardCore.AuditTrail.Services.Models;
using OrchardCore.Modules;
using OrchardCore.Users.Models;

namespace Tor.Account;

/// <summary>Records an account action somewhere besides Tor's own audit log. Names and outcomes only, never values.</summary>
public interface IAccountActionRecorder
{
    Task RecordAsync(User user, string action, IReadOnlyCollection<string> attributes, string outcome);
}

/// <summary>Used while Orchard's Audit Trail is off.</summary>
public sealed class NoAccountActionRecorder : IAccountActionRecorder
{
    public Task RecordAsync(User user, string action, IReadOnlyCollection<string> attributes, string outcome) => Task.CompletedTask;
}

/// <summary>What an Account entry in Orchard's Audit Trail holds: the action, the attribute names and the outcome.</summary>
public class AccountAuditTrailEvent
{
    public string Action { get; set; } = "";
    public string[] Attributes { get; set; } = [];
    public string Outcome { get; set; } = "";
}

/// <summary>The Audit Trail category "Account" and its events (enabled by default, configurable in the Audit Trail settings).</summary>
public sealed class AccountAuditTrailEventConfiguration : IConfigureOptions<AuditTrailOptions>
{
    public const string Category = "Account";

    // Tor's action names -> Audit Trail event names
    public static readonly IReadOnlyDictionary<string, string> Events = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["password"] = "DomainPassword",
        ["picture"] = "DomainPicture",
        ["contact"] = "ContactDetails",
        ["site-picture"] = "SitePicture",
        ["site-picture-remove"] = "SitePictureRemoved",
    };

    public void Configure(AuditTrailOptions options)
    {
        options.For<AccountAuditTrailEventConfiguration>(Category, S => S["Account"])
            .WithEvent("DomainPassword", S => S["Domain password"], S => S["A user changed, or tried to change, their domain password."], true)
            .WithEvent("DomainPicture", S => S["Domain picture"], S => S["A user changed, or tried to change, their domain picture."], true)
            .WithEvent("ContactDetails", S => S["Contact details"], S => S["A user changed, or tried to change, their domain contact details."], true)
            .WithEvent("SitePicture", S => S["Site picture"], S => S["A user changed, or tried to change, their picture on this site."], true)
            .WithEvent("SitePictureRemoved", S => S["Site picture removed"], S => S["A user removed their picture on this site."], true);
    }
}

/// <summary>Writes account actions into Orchard's Audit Trail (who, what, when, outcome).</summary>
public sealed class AuditTrailAccountActionRecorder : IAccountActionRecorder
{
    private readonly IAuditTrailManager _auditTrailManager;

    public AuditTrailAccountActionRecorder(IAuditTrailManager auditTrailManager) => _auditTrailManager = auditTrailManager;

    public Task RecordAsync(User user, string action, IReadOnlyCollection<string> attributes, string outcome)
    {
        if (!AccountAuditTrailEventConfiguration.Events.TryGetValue(action, out var name))
        {
            return Task.CompletedTask;
        }

        return _auditTrailManager.RecordEventAsync(new AuditTrailContext<AccountAuditTrailEvent>(
            name,
            AccountAuditTrailEventConfiguration.Category,
            user.UserId,
            user.UserId,
            user.UserName,
            new AccountAuditTrailEvent { Action = action, Attributes = [.. attributes], Outcome = outcome }));
    }
}

[Feature("Tor.Account")]
[RequireFeatures("OrchardCore.AuditTrail")]
public sealed class AccountAuditTrailStartup : StartupBase
{
    public override void ConfigureServices(IServiceCollection services)
    {
        services.AddTransient<IConfigureOptions<AuditTrailOptions>, AccountAuditTrailEventConfiguration>();
        services.AddScoped<IAccountActionRecorder, AuditTrailAccountActionRecorder>();
    }
}
