// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Contact details: phone rules, the Location list, what gets written, messages and the shared budget.
// No test contacts a domain controller.
using Tor.Account;
using Tor.Directory;
using Tor.Services;
using Xunit;

namespace Tor.Tests;

public class ContactTests
{
    private static readonly IReadOnlyList<string> Locations = ["Head Office", "North Wing", "Reception"];

    [Theory]
    [InlineData("+353 1 234 5678")]
    [InlineData("(01) 234-5678")]
    [InlineData("0871234567")]
    [InlineData("1.234.567")]
    public void Phone_numbers_accepted(string value) => Assert.True(AccountActions.IsPhone(value));

    [Theory]
    [InlineData("call me")]
    [InlineData("+-()")]
    [InlineData("123<script>")]
    [InlineData("12\n34")]
    [InlineData("123;456")]
    [InlineData("０１２３")]
    public void Phone_numbers_refused(string value) => Assert.False(AccountActions.IsPhone(value));

    [Fact]
    public void Phone_length_is_capped_at_the_ad_limit()
    {
        Assert.True(AccountActions.IsPhone(new string('1', AccountActions.MaxPhoneLength)));
        Assert.False(AccountActions.IsPhone(new string('1', AccountActions.MaxPhoneLength + 1)));
    }

    [Fact]
    public void Contact_form_rules()
    {
        var (error, values) = AccountActions.ValidateContact(" 01 234 ", "", "Head Office", Locations, null);
        Assert.Null(error);
        Assert.Equal(new AccountActions.ContactValues("01 234", null, "Head Office"), values);

        // empty fields clear, whitespace counts as empty
        (error, values) = AccountActions.ValidateContact("  ", null, "", Locations, "Head Office");
        Assert.Null(error);
        Assert.Equal(new AccountActions.ContactValues(null, null, null), values);

        // a bad phone or mobile
        Assert.NotNull(AccountActions.ValidateContact("abc", "", "", Locations, null).Error);
        Assert.NotNull(AccountActions.ValidateContact("", "abc", "", Locations, null).Error);

        // a location must come from the list, or be the value AD already holds
        Assert.NotNull(AccountActions.ValidateContact("", "", "Warehouse", Locations, null).Error);
        Assert.NotNull(AccountActions.ValidateContact("", "", "head office", Locations, null).Error);
        Assert.Null(AccountActions.ValidateContact("", "", "Building 7", Locations, "Building 7").Error);
        Assert.NotNull(AccountActions.ValidateContact("", "", "Building 8", Locations, "Building 7").Error);
    }

    [Fact]
    public void Only_changed_attributes_are_written()
    {
        var values = new AccountActions.ContactValues("01 234", null, "Head Office");

        Assert.Empty(AccountActions.ContactChanges(values, "01 234", null, "Head Office"));

        var changes = AccountActions.ContactChanges(values, "01 999", "087 1", "Head Office");
        Assert.Equal(["mobile", "telephoneNumber"], changes.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("01 234", changes["telephoneNumber"]);
        Assert.Null(changes["mobile"]);

        // every name is on the write allow-list
        var all = AccountActions.ContactChanges(new AccountActions.ContactValues("1", "2", "Reception"), null, null, null);
        Assert.All(all.Keys, k => Assert.Contains(k, DirectoryAuthenticator.WritableAttributes));
        Assert.Equal(3, all.Count);
    }

    [Fact]
    public void Location_choices_are_titles_under_the_path()
    {
        var names = LocationChoices.Select(
        [
            ("Head Office", "sites/head-office"),
            ("North Wing", "/sites/north-wing"),
            ("Warehouse", "other/warehouse"),
            ("No route", null),
            ("", "sites/empty"),
            ("Head Office", "sites/head-office-2"),
            (new string('x', AccountActions.MaxOfficeLength + 1), "sites/long"),
            ("annex", "Sites/annex"),
        ], "sites/");

        Assert.Equal(["annex", "Head Office", "North Wing"], names);
    }

    [Fact]
    public void Location_choices_without_a_path_keep_every_title()
    {
        var names = LocationChoices.Select([(" Reception ", null), ("Head Office", "anywhere"), ("", null), ("Reception", null)], "");

        Assert.Equal(["Head Office", "Reception"], names);
    }

    [Fact]
    public void Without_location_choices_the_current_value_is_kept()
    {
        // the controller sends the snapshot's value when no choices are configured: nothing to write for it
        var (error, values) = AccountActions.ValidateContact("01 234", "", "Building 7", [], "Building 7");
        Assert.Null(error);
        Assert.Empty(AccountActions.ContactChanges(values!, "01 234", null, "Building 7"));
    }

    [Fact]
    public void Contact_messages()
    {
        Assert.Equal("Not allowed yet.", AccountActions.ContactMessage(DirectoryWriteOutcome.NotAllowed));
        Assert.Equal("Your current password is not correct.", AccountActions.ContactMessage(DirectoryWriteOutcome.BadCurrentPassword));
        Assert.Equal("Your contact details have been changed.", AccountActions.ContactMessage(DirectoryWriteOutcome.Success));
    }

    [Fact]
    public void Contact_shares_the_attempt_budget()
    {
        var limiter = new ActionLimiter(TimeProvider.System);
        var key = AccountActions.BindKey("user-1");
        Assert.True(limiter.TryAcquire(key, AccountActions.PasswordAttempts, AccountActions.AttemptWindow));
        Assert.True(limiter.TryAcquire(key, AccountActions.PictureAttempts, AccountActions.AttemptWindow));
        Assert.True(limiter.TryAcquire(key, AccountActions.ContactAttempts, AccountActions.AttemptWindow));
        Assert.False(limiter.TryAcquire(key, AccountActions.ContactAttempts, AccountActions.AttemptWindow));
    }
}
