// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Site profile picture: Media paths per user, unguessable names, the 256 pixel re-encode, the model.
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using OrchardCore.Users.Models;
using Tor.Account;
using Tor.Directory;
using Xunit;

namespace Tor.Tests;

public class SitePictureTests
{
    [Fact]
    public void Paths_are_per_user_with_random_names()
    {
        var user = new User { UserId = "4abc123xyz", UserName = "someone" };
        var a = SitePictureStore.NewPath(user);
        var b = SitePictureStore.NewPath(user);

        Assert.StartsWith("site-profile/4abc123xyz/", a);
        Assert.EndsWith(".jpg", a);
        Assert.NotEqual(a, b);
        Assert.Matches("^site-profile/4abc123xyz/[0-9a-f]{32}\\.jpg$", a);
        Assert.DoesNotContain("someone", a);
    }

    [Fact]
    public void User_folder_is_letters_and_digits_only()
    {
        Assert.Equal("abc123", SitePictureStore.UserFolder(new User { UserId = "abc/../123" }));
        Assert.Equal("unknown", SitePictureStore.UserFolder(new User { UserId = "../" }));
    }

    [Fact]
    public void Only_a_path_in_the_users_own_folder_counts()
    {
        var user = new User { UserId = "u1" };
        Assert.True(SitePictureStore.IsOwnPath(user, "site-profile/u1/0123456789abcdef0123456789abcdef.jpg"));
        Assert.False(SitePictureStore.IsOwnPath(user, "site-profile/u2/x.jpg"));
        Assert.False(SitePictureStore.IsOwnPath(user, "other/picture.jpg"));
        Assert.False(SitePictureStore.IsOwnPath(user, "site-profile/u1/../u2/x.jpg"));
        Assert.False(SitePictureStore.IsOwnPath(user, "site-profile/u10/x.jpg"));
    }

    [Fact]
    public void Re_encoded_to_256_pixels_under_the_limit()
    {
        var random = new Random(7);
        using var image = new Image<Rgba32>(700, 500);
        image.ProcessPixelRows(rows =>
        {
            for (var y = 0; y < rows.Height; y++)
            {
                foreach (ref var pixel in rows.GetRowSpan(y))
                {
                    pixel = new Rgba32((byte)random.Next(256), (byte)random.Next(256), (byte)random.Next(256), 255);
                }
            }
        });
        using var input = new MemoryStream();
        image.SaveAsPng(input);

        var result = PictureProcessor.Process(input.ToArray(), SitePictureStore.Size, SitePictureStore.MaxOutputBytes);
        Assert.Equal(PictureOutcome.Ok, result.Outcome);
        Assert.Equal("image/jpeg", DirectorySnapshot.ImageType(result.Jpeg));
        Assert.True(result.Jpeg!.Length <= SitePictureStore.MaxOutputBytes);
        using var output = Image.Load(result.Jpeg);
        Assert.Equal((256, 256), (output.Width, output.Height));
    }

    [Fact]
    public void Same_file_checks_as_the_domain_picture()
    {
        Assert.Equal(PictureOutcome.WrongType, PictureProcessor.Process("GIF89a.."u8, SitePictureStore.Size, SitePictureStore.MaxOutputBytes).Outcome);
        Assert.Equal(PictureOutcome.Missing, PictureProcessor.Process([], SitePictureStore.Size, SitePictureStore.MaxOutputBytes).Outcome);
    }

    [Fact]
    public void Profile_model_carries_the_site_picture_for_local_accounts_too()
    {
        var model = new AccountProfileViewModel();
        AccountProfileDisplayDriver.Fill(model, new AccountPage
        {
            User = new User { UserName = "admin" },
            IsLocal = true,
            SitePictureUrl = "/media/site-profile/u1/x.jpg",
        });

        Assert.True(model.IsLocal);
        Assert.Equal("/media/site-profile/u1/x.jpg", model.SitePictureUrl);
        Assert.Null(model.PhotoUrl);
    }
}
