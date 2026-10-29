// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Account audit: every action has an Audit Trail event, and an entry can only hold names and outcomes.
using System.Text.RegularExpressions;
using Tor.Account;
using Xunit;

namespace Tor.Tests;

public class AccountAuditTests
{
    [Fact]
    public void Every_controller_action_has_an_audit_trail_event()
    {
        var source = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "Tor", "Controllers", "AccountController.cs"));
        var actions = Regex.Matches(source, @"RecordAsync\(user, client, ""([a-z-]+)""").Select(m => m.Groups[1].Value).Distinct().ToList();

        Assert.NotEmpty(actions);
        Assert.All(actions, a => Assert.True(AccountAuditTrailEventConfiguration.Events.ContainsKey(a), a));
    }

    [Fact]
    public void An_entry_holds_names_and_outcome_only()
    {
        Assert.Equal(["Action", "Attributes", "Outcome"], typeof(AccountAuditTrailEvent).GetProperties().Select(p => p.Name).Order());
    }

    [Fact]
    public void Without_audit_trail_nothing_is_recorded() =>
        Assert.True(new NoAccountActionRecorder().RecordAsync(new OrchardCore.Users.Models.User(), "password", ["unicodePwd"], "success").IsCompletedSuccessfully);
}
