// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using Tor.Directory;

namespace Tor.Account;

public enum PictureOutcome
{
    Ok,
    Missing,
    TooLarge,
    WrongType,
    TooManyPixels,
    Unreadable,
}

/// <summary>The checked and re-encoded picture: a 96x96 baseline JPEG without metadata, under 100 KB.</summary>
public sealed record PictureResult(PictureOutcome Outcome, byte[]? Jpeg = null);

/// <summary>
/// Turns an uploaded file into the domain picture. Only JPEG and PNG, by their signature, up to 2 MB.
/// Only the JPEG and PNG decoders are loaded, one frame only, no metadata is parsed, and the size in the header is checked
/// before any pixels are decoded. The result is always newly encoded, so nothing of the upload survives
/// but the pixels.
/// </summary>
public static class PictureProcessor
{
    public const long MaxUploadBytes = 2 * 1024 * 1024;
    public const int Size = 96;
    public const int MaxOutputBytes = DirectorySnapshot.MaxPhotoBytes;

    // 40 million pixels (e.g. 8000 x 5000) is far beyond any photo meant for a 96 pixel picture
    public const long MaxPixels = 40_000_000;
    public const int MaxSide = 12_000;

    private static readonly DecoderOptions _decoderOptions = new()
    {
        Configuration = new Configuration(new JpegConfigurationModule(), new PngConfigurationModule()),
        MaxFrames = 1,

        // no ICC, EXIF or XMP parsing at all: ImageSharp 3.1.12 has an ICC parsing advisory (GHSA-gwg2-r3hj-4w44).
        // The price: EXIF rotation is not applied, so a sideways phone photo stays sideways.
        SkipMetadata = true,
    };

    public static PictureResult Process(ReadOnlySpan<byte> upload) => Process(upload, Size, MaxOutputBytes);

    /// <summary>The same checks, re-encoded to a <paramref name="size"/> square JPEG of at most <paramref name="maxOutputBytes"/>.</summary>
    public static PictureResult Process(ReadOnlySpan<byte> upload, int size, int maxOutputBytes)
    {
        if (upload.IsEmpty)
        {
            return new PictureResult(PictureOutcome.Missing);
        }

        if (upload.Length > MaxUploadBytes)
        {
            return new PictureResult(PictureOutcome.TooLarge);
        }

        if (DirectorySnapshot.ImageType(upload) is null)
        {
            return new PictureResult(PictureOutcome.WrongType);
        }

        try
        {
            var info = Image.Identify(_decoderOptions, upload);
            if (info.Width <= 0 || info.Height <= 0 || info.Width > MaxSide || info.Height > MaxSide || (long)info.Width * info.Height > MaxPixels)
            {
                return new PictureResult(PictureOutcome.TooManyPixels);
            }

            using var image = Image.Load<Rgba32>(_decoderOptions, upload);
            image.Mutate(x => x
                .Resize(new ResizeOptions { Size = new Size(size, size), Mode = ResizeMode.Crop, Position = AnchorPositionMode.Center })
                .BackgroundColor(Color.White));

            image.Metadata.ExifProfile = null;
            image.Metadata.IccProfile = null;
            image.Metadata.IptcProfile = null;
            image.Metadata.XmpProfile = null;

            foreach (var quality in new[] { 88, 75, 60, 45, 30, 20 })
            {
                using var output = new MemoryStream();
                image.SaveAsJpeg(output, new JpegEncoder { Quality = quality, ColorType = JpegEncodingColor.YCbCrRatio420 });
                if (output.Length <= maxOutputBytes)
                {
                    return new PictureResult(PictureOutcome.Ok, output.ToArray());
                }
            }

            return new PictureResult(PictureOutcome.TooLarge);
        }
        catch (Exception)
        {
            // any decoder failure (it throws more than its own exception types on malformed input) means unreadable
            return new PictureResult(PictureOutcome.Unreadable);
        }
    }

    public static string Message(PictureOutcome outcome) => outcome switch
    {
        PictureOutcome.Missing => "Choose a picture to upload.",
        PictureOutcome.TooLarge => "The picture can be at most 2 MB.",
        PictureOutcome.WrongType => "The picture must be a JPEG or PNG file.",
        PictureOutcome.TooManyPixels => "The picture is too large in pixels. Use one of at most 12,000 pixels on each side.",
        _ => "The picture could not be read. Try another JPEG or PNG file.",
    };
}
