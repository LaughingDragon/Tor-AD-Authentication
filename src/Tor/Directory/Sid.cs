// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;

namespace Tor.Directory;

/// <summary>Binary security identifier (objectSid, tokenGroups) to its "S-1-5-21-..." text form.</summary>
public static class Sid
{
    public static string? ToText(ReadOnlySpan<byte> bytes)
    {
        // revision(1) count(1) authority(6, big-endian) sub-authorities(4 each, little-endian)
        if (bytes.Length < 8 || bytes[0] != 1)
        {
            return null;
        }

        int count = bytes[1];
        if (count > 15 || bytes.Length != 8 + 4 * count)
        {
            return null;
        }

        ulong authority = 0;
        for (var i = 2; i < 8; i++)
        {
            authority = (authority << 8) | bytes[i];
        }

        var text = new StringBuilder("S-1-").Append(authority);
        for (var i = 0; i < count; i++)
        {
            text.Append('-').Append(BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(8 + 4 * i, 4)));
        }

        return text.ToString();
    }
}
