// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// The Account area: snapshot values, attribute allow-list, permissions and the profile shape model.
using OrchardCore.Users.Models;
using Tor.Account;
using Tor.Directory;
using Xunit;

namespace Tor.Tests;

public class AccountTests
{
    [Theory]
    [InlineData("Alice@Corp.Example.COM", "Alice@corp.example.com")]
    [InlineData("  name@Example.COM ", "name@example.com")]
    [InlineData("no-at-sign", "no-at-sign")]
    [InlineData("a@b@C.D", "a@b@c.d")]
    public void Domain_part_is_lower_cased_only(string input, string expected) =>
        Assert.Equal(expected, DirectorySnapshot.LowerDomain(input));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_values_are_null(string? input)
    {
        Assert.Null(DirectorySnapshot.Cap(input));
        Assert.Null(DirectorySnapshot.LowerDomain(input));
    }

    [Fact]
    public void Values_are_capped()
    {
        Assert.Equal(DirectorySnapshot.MaxText, DirectorySnapshot.Cap(new string('x', 5000))!.Length);
        Assert.Equal(DirectorySnapshot.MaxDescription, DirectorySnapshot.Cap(new string('x', 5000), DirectorySnapshot.MaxDescription)!.Length);
    }

    [Fact]
    public void Lists_are_trimmed_deduplicated_sorted_and_capped()
    {
        Assert.Equal(["a", "B"], DirectorySnapshot.CapList(["B", " a ", "A", "", null]));
        Assert.Equal(DirectorySnapshot.MaxListItems, DirectorySnapshot.CapList(Enumerable.Range(0, 500).Select(i => "pc" + i)).Count);
    }

    [Theory]
    [InlineData("0", null)]
    [InlineData("9223372036854775807", null)]
    [InlineData("not a number", null)]
    [InlineData("-1", null)]
    public void File_times(string input, string? expected) =>
        Assert.Equal(expected is null ? null : DateTime.Parse(expected, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal),
            DirectorySnapshot.FromFileTime(input));

    [Fact]
    public void File_time_round_trips_as_utc()
    {
        var when = new DateTime(2025, 10, 26, 9, 45, 0, DateTimeKind.Utc);
        var read = DirectorySnapshot.FromFileTime(when.ToFileTimeUtc().ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(when, read);
        Assert.Equal(DateTimeKind.Utc, read!.Value.Kind);
    }

    [Theory]
    [InlineData("20261023081500.0Z", 2026, 10, 23, 8, 15, 0)]
    [InlineData("20261023081500Z", 2026, 10, 23, 8, 15, 0)]
    public void Generalized_time(string input, int y, int mo, int d, int h, int mi, int s)
    {
        var time = DirectorySnapshot.FromGeneralizedTime(input);
        Assert.Equal(new DateTime(y, mo, d, h, mi, s, DateTimeKind.Utc), time);
        Assert.Equal(DateTimeKind.Utc, time!.Value.Kind);
    }

    [Theory]
    [InlineData("")]
    [InlineData("yesterday")]
    [InlineData("2026-10-23")]
    public void Bad_generalized_time_is_null(string input) => Assert.Null(DirectorySnapshot.FromGeneralizedTime(input));

    [Fact]
    public void Image_types_by_signature()
    {
        Assert.Equal("image/jpeg", DirectorySnapshot.ImageType([0xFF, 0xD8, 0xFF, 0xE0, 0, 0]));
        Assert.Equal("image/png", DirectorySnapshot.ImageType([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0]));
        Assert.Null(DirectorySnapshot.ImageType("GIF89a"u8));
        Assert.Null(DirectorySnapshot.ImageType("<svg"u8));
        Assert.Null(DirectoryServicesEmpty());
        Assert.Null(DirectorySnapshot.ImageType([0xFF, 0xD8]));

        static string? DirectoryServicesEmpty() => DirectorySnapshot.ImageType([]);
    }

    [Fact]
    public void Snapshot_reads_only_the_allow_list()
    {
        Assert.Equal(
            ["title", "department", "description", "telephoneNumber", "mobile", "physicalDeliveryOfficeName",
             "whenCreated", "pwdLastSet", "msDS-UserPasswordExpiryTimeComputed", "lastLogonTimestamp", "homeDirectory", "thumbnailPhoto"],
            DirectoryAuthenticator.SnapshotAttributes);

        // never a password attribute
        Assert.DoesNotContain(DirectoryAuthenticator.SnapshotAttributes.Concat(DirectoryAuthenticator.AccountAttributes),
            a => a.Contains("pwd", StringComparison.OrdinalIgnoreCase) && a != "pwdLastSet" || a.Equals("unicodePwd", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Part_stores_the_snapshot()
    {
        var synced = new DateTime(2026, 10, 26, 9, 0, 0, DateTimeKind.Utc);
        var part = new DirectoryProfilePart();
        part.Apply(new DirectorySnapshot
        {
            DisplayName = "Test User",
            Mail = "test@example.com",
            Groups = ["Intranet-Users"],
            ManagedComputers = ["pc1.example.com"],
            Enabled = true,
            Photo = [0xFF, 0xD8, 0xFF, 0xE0],
            PhotoContentType = "image/jpeg",
        }, synced);

        Assert.Equal(synced, part.SyncedUtc);
        Assert.Equal("Test User", part.DisplayName);
        Assert.Equal(["Intranet-Users"], part.Groups);
        Assert.Equal(["pc1.example.com"], part.ManagedComputers);
        Assert.Equal(Convert.ToBase64String([0xFF, 0xD8, 0xFF, 0xE0]), part.Photo);

        // a later snapshot without a photo clears it
        part.Apply(new DirectorySnapshot { DisplayName = "Test User" }, synced);
        Assert.Null(part.Photo);
        Assert.Null(part.PhotoContentType);
        Assert.Empty(part.Groups);
    }

    [Fact]
    public void Profile_model_from_the_snapshot()
    {
        var part = new DirectoryProfilePart
        {
            SyncedUtc = DateTime.UtcNow,
            DisplayName = "Test User",
            Photo = Convert.ToBase64String([0xFF, 0xD8, 0xFF]),
            PhotoContentType = "image/jpeg",
            PasswordExpiresUtc = null,
            AccountExpiresUtc = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        };
        var model = new AccountProfileViewModel();
        AccountProfileDisplayDriver.Fill(model, new AccountPage { User = new User { UserName = "test" }, IsLocal = false, Profile = part });

        Assert.True(model.HasSnapshot);
        Assert.Equal("test", model.UserName);
        Assert.Equal("Test User", model.DisplayName);
        Assert.True(model.PasswordNeverExpires);
        Assert.False(model.AccountNeverExpires);
        Assert.Equal("/account/picture", model.PhotoUrl);
    }

    [Fact]
    public void Profile_model_refuses_other_photo_types()
    {
        var part = new DirectoryProfilePart { SyncedUtc = DateTime.UtcNow, Photo = "PHN2Zz4=", PhotoContentType = "image/svg+xml" };
        var model = new AccountProfileViewModel();
        AccountProfileDisplayDriver.Fill(model, new AccountPage { User = new User { UserName = "test" }, IsLocal = false, Profile = part });
        Assert.Null(model.PhotoUrl);
    }

    [Fact]
    public void Picture_is_served_only_when_bytes_match_the_type()
    {
        byte[] jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2];
        Assert.Equal("image/jpeg", AccountProfileDisplayDriver.PhotoOf(new DirectoryProfilePart { Photo = Convert.ToBase64String(jpeg), PhotoContentType = "image/jpeg" })?.ContentType);

        // stored type and signature disagree, not base64, or too big
        Assert.Null(AccountProfileDisplayDriver.PhotoOf(new DirectoryProfilePart { Photo = Convert.ToBase64String(jpeg), PhotoContentType = "image/png" }));
        Assert.Null(AccountProfileDisplayDriver.PhotoOf(new DirectoryProfilePart { Photo = "not base64!", PhotoContentType = "image/jpeg" }));
        var big = new byte[DirectorySnapshot.MaxPhotoBytes + 1];
        jpeg.CopyTo(big, 0);
        Assert.Null(AccountProfileDisplayDriver.PhotoOf(new DirectoryProfilePart { Photo = Convert.ToBase64String(big), PhotoContentType = "image/jpeg" }));
    }

    [Fact]
    public void Local_account_shows_no_directory_details()
    {
        var model = new AccountProfileViewModel();
        AccountProfileDisplayDriver.Fill(model, new AccountPage
        {
            User = new User { UserName = "admin" },
            IsLocal = true,
            Profile = new DirectoryProfilePart { SyncedUtc = DateTime.UtcNow, DisplayName = "should not show" },
        });

        Assert.True(model.IsLocal);
        Assert.False(model.HasSnapshot);
        Assert.Null(model.DisplayName);
    }

    [Fact]
    public void Permissions_and_default_grants()
    {
        var provider = new AccountPermissions();
        var all = provider.GetPermissionsAsync().Result.Select(p => p.Name).ToList();
        Assert.Contains("ManageOwnAccount", all);

        // every action permission is implied by ManageOwnAccount
        foreach (var permission in new[] { AccountPermissions.ViewOwnAccount, AccountPermissions.ChangeOwnDomainPassword, AccountPermissions.ChangeOwnDomainPicture, AccountPermissions.ChangeOwnContactDetails, AccountPermissions.ChangeOwnSitePicture })
        {
            Assert.Contains(AccountPermissions.ManageOwnAccount, permission.ImpliedBy);
        }

        var stereotypes = provider.GetDefaultStereotypes().ToDictionary(s => s.Name, s => s.Permissions.Select(p => p.Name).Order().ToList());
        Assert.Equal(["ManageOwnAccount"], stereotypes["Intranet Users"]);
        Assert.Equal(["ChangeOwnDomainPassword", "ChangeOwnSitePicture", "ViewOwnAccount"], stereotypes["Guests"]);
    }
}
