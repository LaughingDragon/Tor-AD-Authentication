// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.DirectoryServices.Protocols;
using System.Text;

namespace Tor.Directory;

public enum DirectoryWriteOutcome
{
    Success,
    BadCurrentPassword,
    PolicyViolation,
    NotAllowed,
    WrongAccount,
    NotSecure,
    Unavailable,
    Refused,
}

/// <summary>What one write told us; Snapshot is the user's entry re-read after a successful write (may be null).</summary>
public sealed record DirectoryWriteResult(DirectoryWriteOutcome Outcome, DirectorySnapshot? Snapshot = null);

/// <summary>
/// Writes to the signed-in user's own directory object, binding as that user with the password typed in
/// the form at that moment. The bind's own entry is the only target, and its SID must match the Orchard
/// user's linked SID. No service account, nothing stored.
/// </summary>
public interface IDirectoryWriter
{
    DirectoryWriteResult ChangePassword(AccountName account, string expectedSid, string currentPassword, string newPassword);

    /// <summary>Replaces (or, for null, clears) attributes from <see cref="DirectoryAuthenticator.WritableAttributes"/> only.</summary>
    DirectoryWriteResult Replace(AccountName account, string expectedSid, string password, IReadOnlyDictionary<string, object?> values);
}

public sealed partial class DirectoryAuthenticator : IDirectoryWriter
{
    /// <summary>The allow-list of attributes an account action may write (besides the password).</summary>
    internal static readonly HashSet<string> WritableAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "thumbnailPhoto", "telephoneNumber", "mobile", "physicalDeliveryOfficeName",
    };

    public DirectoryWriteResult ChangePassword(AccountName account, string expectedSid, string currentPassword, string newPassword)
    {
        // AD only accepts unicodePwd over an encrypted connection; this module requires LDAPS for it
        if (!_options.UseLdaps)
        {
            return new DirectoryWriteResult(DirectoryWriteOutcome.NotSecure);
        }

        // a user's own change: delete the old value and add the new one in the same modify
        return Modify(account, expectedSid, currentPassword,
        [
            new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Delete }.With(PasswordValue(currentPassword)),
            new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Add }.With(PasswordValue(newPassword)),
        ]);
    }

    public DirectoryWriteResult Replace(AccountName account, string expectedSid, string password, IReadOnlyDictionary<string, object?> values)
    {
        if (values.Count == 0 || values.Keys.Any(k => !WritableAttributes.Contains(k)))
        {
            return new DirectoryWriteResult(DirectoryWriteOutcome.Refused);
        }

        var changes = new List<DirectoryAttributeModification>();
        foreach (var (name, value) in values)
        {
            var change = new DirectoryAttributeModification { Name = name, Operation = DirectoryAttributeOperation.Replace };
            switch (value)
            {
                case null:
                    // replace with no values clears the attribute (and is fine when it is already empty)
                    break;
                case string text:
                    change.Add(text);
                    break;
                case byte[] bytes:
                    change.Add(bytes);
                    break;
                default:
                    return new DirectoryWriteResult(DirectoryWriteOutcome.Refused);
            }

            changes.Add(change);
        }

        return Modify(account, expectedSid, password, changes);
    }

    private DirectoryWriteResult Modify(AccountName account, string expectedSid, string password, IReadOnlyList<DirectoryAttributeModification> changes)
    {
        if (_options.Servers.Length == 0 || string.IsNullOrEmpty(password))
        {
            return new DirectoryWriteResult(string.IsNullOrEmpty(password) ? DirectoryWriteOutcome.BadCurrentPassword : DirectoryWriteOutcome.Unavailable);
        }

        using var connection = Open(_options, account, password);
        try
        {
            connection.Bind();
        }
        catch (LdapException ex)
        {
            return new DirectoryWriteResult(ClassifyBindFailure(ex) switch
            {
                DirectoryOutcome.BadCredentials => DirectoryWriteOutcome.BadCurrentPassword,
                DirectoryOutcome.Unavailable => DirectoryWriteOutcome.Unavailable,
                _ => DirectoryWriteOutcome.Refused,
            });
        }

        string distinguishedName;
        try
        {
            if (FindSelf(connection) is not var (_, dn))
            {
                return new DirectoryWriteResult(DirectoryWriteOutcome.Refused);
            }

            // the bind's own entry must be the Orchard user's linked account
            var entry = ((SearchResponse)connection.SendRequest(new SearchRequest(dn, "(objectClass=user)", SearchScope.Base, "objectSid"))).Entries[0];
            var sid = entry.Attributes["objectSid"]?.GetValues(typeof(byte[])) is [byte[] bytes, ..] ? Sid.ToText(bytes) : null;
            if (sid is null || !string.Equals(sid, expectedSid, StringComparison.OrdinalIgnoreCase))
            {
                return new DirectoryWriteResult(DirectoryWriteOutcome.WrongAccount);
            }

            distinguishedName = dn;
            connection.SendRequest(new ModifyRequest(distinguishedName, [.. changes]));
        }
        catch (DirectoryOperationException ex)
        {
            return new DirectoryWriteResult(ClassifyWriteFailure(ex.Response?.ResultCode));
        }
        catch (LdapException)
        {
            return new DirectoryWriteResult(DirectoryWriteOutcome.Unavailable);
        }

        // the write is done; a fresh snapshot is a bonus (the bind stays valid after a password change)
        try
        {
            var reread = ReadAccount(connection);
            return new DirectoryWriteResult(DirectoryWriteOutcome.Success, reread.Outcome == DirectoryOutcome.Success ? reread.Snapshot : null);
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException)
        {
            return new DirectoryWriteResult(DirectoryWriteOutcome.Success);
        }
    }

    internal static DirectoryWriteOutcome ClassifyWriteFailure(ResultCode? code) => code switch
    {
        // 0000052D and friends: length, complexity, history, minimum age; also attribute size limits
        ResultCode.ConstraintViolation => DirectoryWriteOutcome.PolicyViolation,
        ResultCode.InsufficientAccessRights => DirectoryWriteOutcome.NotAllowed,
        ResultCode.Busy or ResultCode.Unavailable => DirectoryWriteOutcome.Unavailable,
        _ => DirectoryWriteOutcome.Refused,
    };

    // AD wants the password in double quotes, UTF-16LE
    internal static byte[] PasswordValue(string password) => Encoding.Unicode.GetBytes("\"" + password + "\"");
}

internal static class DirectoryAttributeModificationExtensions
{
    public static DirectoryAttributeModification With(this DirectoryAttributeModification change, byte[] value)
    {
        change.Add(value);
        return change;
    }
}
