// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Domain picture: signature check, size limits, re-encode, messages and the shared attempt budget.
// Images are generated in memory; no test contacts a domain controller.
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Metadata.Profiles.Exif;
using SixLabors.ImageSharp.PixelFormats;
using Tor.Account;
using Tor.Directory;
using Tor.Services;
using Xunit;

namespace Tor.Tests;

public class PictureTests
{
    [Fact]
    public void Only_jpeg_and_png_signatures_pass()
    {
        Assert.Equal(PictureOutcome.Missing, PictureProcessor.Process([]).Outcome);
        Assert.Equal(PictureOutcome.WrongType, PictureProcessor.Process("GIF89a\u0001\u0000\u0001\u0000"u8).Outcome);
        Assert.Equal(PictureOutcome.WrongType, PictureProcessor.Process("BM\u0000\u0000\u0000\u0000"u8).Outcome);
        Assert.Equal(PictureOutcome.WrongType, PictureProcessor.Process("<svg xmlns=\"http://www.w3.org/2000/svg\"/>"u8).Outcome);
        Assert.Equal(PictureOutcome.WrongType, PictureProcessor.Process("RIFF\u0000\u0000\u0000\u0000WEBPVP8 "u8).Outcome);
        Assert.Equal(PictureOutcome.WrongType, PictureProcessor.Process("II*\u0000"u8).Outcome);

        // a JPEG or PNG renamed is judged by its bytes, not its name: a real PNG passes
        Assert.Equal(PictureOutcome.Ok, PictureProcessor.Process(Png(40, 30)).Outcome);
        Assert.Equal(PictureOutcome.Ok, PictureProcessor.Process(Jpeg(40, 30)).Outcome);
    }

    [Fact]
    public void Uploads_over_2_MB_are_refused_before_decoding()
    {
        var big = new byte[PictureProcessor.MaxUploadBytes + 1];
        big[0] = 0xFF;
        big[1] = 0xD8;
        big[2] = 0xFF;
        Assert.Equal(PictureOutcome.TooLarge, PictureProcessor.Process(big).Outcome);

        // exactly 2 MB is the limit, not over it (this one is not a valid JPEG, so it fails later)
        var limit = new byte[PictureProcessor.MaxUploadBytes];
        limit[0] = 0xFF;
        limit[1] = 0xD8;
        limit[2] = 0xFF;
        Assert.Equal(PictureOutcome.Unreadable, PictureProcessor.Process(limit).Outcome);
    }

    [Fact]
    public void Huge_dimensions_are_refused_from_the_header()
    {
        Assert.Equal(PictureOutcome.TooManyPixels, PictureProcessor.Process(PngWithHeaderSize(20_000, 20_000)).Outcome);
        Assert.Equal(PictureOutcome.TooManyPixels, PictureProcessor.Process(PngWithHeaderSize(PictureProcessor.MaxSide + 1, 10)).Outcome);
    }

    [Fact]
    public void Broken_files_are_unreadable()
    {
        byte[] pngHeaderOnly = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8];
        Assert.Equal(PictureOutcome.Unreadable, PictureProcessor.Process(pngHeaderOnly).Outcome);

        var truncated = Jpeg(200, 200)[..300];
        Assert.NotEqual(PictureOutcome.Ok, PictureProcessor.Process(truncated).Outcome);
    }

    [Theory]
    [InlineData(400, 300)]
    [InlineData(300, 900)]
    [InlineData(96, 96)]
    [InlineData(20, 10)]
    [InlineData(800, 600)]
    public void Re_encoded_to_a_96_pixel_jpeg_under_100_KB(int width, int height)
    {
        var result = PictureProcessor.Process(Noise(width, height));

        Assert.Equal(PictureOutcome.Ok, result.Outcome);
        Assert.Equal("image/jpeg", DirectorySnapshot.ImageType(result.Jpeg));
        Assert.True(result.Jpeg!.Length <= PictureProcessor.MaxOutputBytes);
        using var output = Image.Load(result.Jpeg);
        Assert.Equal(PictureProcessor.Size, output.Width);
        Assert.Equal(PictureProcessor.Size, output.Height);
    }

    [Fact]
    public void Large_photo_with_a_small_file_is_scaled_down()
    {
        var result = PictureProcessor.Process(Png(4000, 3000));
        Assert.Equal(PictureOutcome.Ok, result.Outcome);
        using var output = Image.Load(result.Jpeg!);
        Assert.Equal((PictureProcessor.Size, PictureProcessor.Size), (output.Width, output.Height));
    }

    [Fact]
    public void Metadata_does_not_survive()
    {
        using var image = new Image<Rgba32>(120, 80, Color.CornflowerBlue);
        image.Metadata.ExifProfile = new ExifProfile();
        image.Metadata.ExifProfile.SetValue(ExifTag.Artist, "someone");
        image.Metadata.ExifProfile.SetValue(ExifTag.GPSLatitudeRef, "N");
        using var input = new MemoryStream();
        image.SaveAsJpeg(input);

        var result = PictureProcessor.Process(input.ToArray());
        Assert.Equal(PictureOutcome.Ok, result.Outcome);
        using var output = Image.Load(result.Jpeg!);
        Assert.Null(output.Metadata.ExifProfile);
        Assert.Null(output.Metadata.XmpProfile);
        Assert.Null(output.Metadata.IptcProfile);
    }

    [Fact]
    public void Transparent_png_gets_a_white_background()
    {
        using var image = new Image<Rgba32>(50, 50, new Rgba32(0, 0, 0, 0));
        using var input = new MemoryStream();
        image.SaveAsPng(input);

        var result = PictureProcessor.Process(input.ToArray());
        Assert.Equal(PictureOutcome.Ok, result.Outcome);
        using var output = Image.Load<Rgb24>(result.Jpeg!);
        var pixel = output[48, 48];
        Assert.True(pixel.R > 240 && pixel.G > 240 && pixel.B > 240);
    }

    [Fact]
    public void Picture_messages()
    {
        foreach (var refused in new[] { DirectoryWriteOutcome.NotAllowed, DirectoryWriteOutcome.PolicyViolation, DirectoryWriteOutcome.Refused, DirectoryWriteOutcome.WrongAccount, DirectoryWriteOutcome.NotSecure })
        {
            Assert.Equal("Not allowed yet.", AccountActions.PictureMessage(refused));
        }

        Assert.Equal("Your current password is not correct.", AccountActions.PictureMessage(DirectoryWriteOutcome.BadCurrentPassword));
        Assert.NotNull(AccountActions.ValidateCurrentPassword(""));
        Assert.NotNull(AccountActions.ValidateCurrentPassword(new string('x', AccountActions.MaxPasswordLength + 1)));
        Assert.Null(AccountActions.ValidateCurrentPassword("made-up"));
    }

    [Fact]
    public void Picture_and_password_share_one_attempt_budget()
    {
        var limiter = new ActionLimiter(TimeProvider.System);
        var key = AccountActions.BindKey("user-1");

        Assert.True(limiter.TryAcquire(key, AccountActions.PasswordAttempts, AccountActions.AttemptWindow));
        Assert.True(limiter.TryAcquire(key, AccountActions.PictureAttempts, AccountActions.AttemptWindow));
        Assert.True(limiter.TryAcquire(key, AccountActions.PictureAttempts, AccountActions.AttemptWindow));
        Assert.False(limiter.TryAcquire(key, AccountActions.PasswordAttempts, AccountActions.AttemptWindow));
        Assert.False(limiter.TryAcquire(key, AccountActions.PictureAttempts, AccountActions.AttemptWindow));
        Assert.True(limiter.TryAcquire(AccountActions.BindKey("user-2"), AccountActions.PictureAttempts, AccountActions.AttemptWindow));
    }

    [Fact]
    public void Only_thumbnail_photo_is_written_for_the_picture()
    {
        Assert.Contains("thumbnailPhoto", DirectoryAuthenticator.WritableAttributes);
        Assert.Equal(DirectorySnapshot.MaxPhotoBytes, PictureProcessor.MaxOutputBytes);
    }

    private static byte[] Png(int width, int height)
    {
        using var image = new Image<Rgba32>(width, height, Color.SeaGreen);
        using var stream = new MemoryStream();
        image.SaveAsPng(stream);
        return stream.ToArray();
    }

    private static byte[] Jpeg(int width, int height)
    {
        using var image = new Image<Rgba32>(width, height, Color.SteelBlue);
        using var stream = new MemoryStream();
        image.SaveAsJpeg(stream);
        return stream.ToArray();
    }

    // random pixels compress badly: the worst case for the 100 KB limit
    private static byte[] Noise(int width, int height)
    {
        var random = new Random(42);
        using var image = new Image<Rgba32>(width, height);
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
        using var stream = new MemoryStream();
        image.SaveAsPng(stream);
        return stream.ToArray();
    }

    // a valid 1x1 PNG whose IHDR claims another size (CRC fixed up), so only the header is ever read
    private static byte[] PngWithHeaderSize(int width, int height)
    {
        var png = Png(1, 1);
        // signature (8), length (4), "IHDR" (4), then width and height big-endian
        WriteBigEndian(png, 16, width);
        WriteBigEndian(png, 20, height);
        WriteBigEndian(png, 29, (int)Crc32(png.AsSpan(12, 17)));
        return png;
    }

    private static void WriteBigEndian(byte[] buffer, int offset, int value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)value;
    }

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc ^= b;
            for (var i = 0; i < 8; i++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
        }

        return ~crc;
    }
}
