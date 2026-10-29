// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Tor.Directory;

namespace Tor.Account;

/// <summary>Input rules and user-facing messages for the account actions. Messages never contain a typed value.</summary>
public static class AccountActions
{
    public const int MaxPasswordLength = 256;
    public const int PasswordAttempts = 3;
    public static readonly TimeSpan AttemptWindow = TimeSpan.FromMinutes(15);

    public const string PasswordPath = "/account/password";

    /// <summary>Element id of the password panel; failures redirect to /account#account-password.</summary>
    public const string PasswordPanelId = "account-password";

    /// <summary>Null when the three fields are acceptable to send to the directory, else the message to show.</summary>
    public static string? ValidatePassword(string? current, string? next, string? confirm)
    {
        if (string.IsNullOrEmpty(current) || string.IsNullOrEmpty(next) || string.IsNullOrEmpty(confirm))
        {
            return "Fill in all three password fields.";
        }

        if (current.Length > MaxPasswordLength || next.Length > MaxPasswordLength)
        {
            return $"Passwords can be at most {MaxPasswordLength} characters.";
        }

        if (!string.Equals(next, confirm, StringComparison.Ordinal))
        {
            return "The new password and its confirmation do not match.";
        }

        if (string.Equals(current, next, StringComparison.Ordinal))
        {
            return "The new password must be different from the current one.";
        }

        // a control character can't be typed on purpose and isn't accepted by the directory anyway
        if (next.Any(char.IsControl))
        {
            return "The new password contains a character that can't be used.";
        }

        return null;
    }

    public static string PasswordMessage(DirectoryWriteOutcome outcome) => outcome switch
    {
        DirectoryWriteOutcome.Success => "Your domain password has been changed. Use the new password from now on, also on your computer.",
        DirectoryWriteOutcome.BadCurrentPassword => "Your current password is not correct.",
        DirectoryWriteOutcome.PolicyViolation => "The domain did not accept the new password. It must follow the domain's password rules: long enough, complex enough, not one of your recent passwords, and not changed again too soon after the last change.",
        DirectoryWriteOutcome.NotAllowed => "The domain does not allow this account to change its password here.",
        DirectoryWriteOutcome.Unavailable => "The domain can't be reached right now. Your password was not changed. Try again later.",
        _ => "Your password was not changed.",
    };

    public const string PicturePath = "/account/picture";
    public const string PicturePanelId = "account-picture";
    public const int PictureAttempts = 3;

    /// <summary>One budget for every action that binds with a typed password, so sign-in failures plus these stay below the domain lockout.</summary>
    public static string BindKey(string userId) => "bind:" + userId;

    /// <summary>Null when the current password is acceptable to bind with, else the message to show.</summary>
    public static string? ValidateCurrentPassword(string? current) =>
        string.IsNullOrEmpty(current) ? "Enter your current password." :
        current.Length > MaxPasswordLength ? $"Passwords can be at most {MaxPasswordLength} characters." :
        null;

    /// <summary>For the domain picture: any refusal by AD reads "Not allowed yet."</summary>
    public static string PictureMessage(DirectoryWriteOutcome outcome) => outcome switch
    {
        DirectoryWriteOutcome.Success => "Your domain picture has been changed.",
        DirectoryWriteOutcome.BadCurrentPassword => "Your current password is not correct.",
        DirectoryWriteOutcome.Unavailable => "The domain can't be reached right now. Your picture was not changed. Try again later.",
        _ => "Not allowed yet.",
    };

    public const string ContactPath = "/account/contact";
    public const string ContactPanelId = "account-contact";
    public const int ContactAttempts = 3;
    public const int MaxPhoneLength = 64;
    public const int MaxOfficeLength = 128;

    /// <summary>The three contact values to write, as they should end up in AD (null clears).</summary>
    public sealed record ContactValues(string? TelephoneNumber, string? Mobile, string? Office);

    /// <summary>
    /// Checks the contact form. Phones: empty, or digits, spaces and + - ( ) . with at least one digit, at most 64.
    /// Location: empty, one of the offered names, or the value AD already holds (so saving phones never clears it).
    /// </summary>
    public static (string? Error, ContactValues? Values) ValidateContact(string? phone, string? mobile, string? office, IReadOnlyList<string> offices, string? currentOffice)
    {
        var phoneValue = Blank(phone);
        var mobileValue = Blank(mobile);
        var officeValue = Blank(office);

        if (phoneValue is not null && !IsPhone(phoneValue))
        {
            return ("The phone number can only contain digits, spaces and + - ( ) . (at most 64 characters).", null);
        }

        if (mobileValue is not null && !IsPhone(mobileValue))
        {
            return ("The mobile number can only contain digits, spaces and + - ( ) . (at most 64 characters).", null);
        }

        if (officeValue is not null && !offices.Contains(officeValue, StringComparer.Ordinal) && !string.Equals(officeValue, currentOffice, StringComparison.Ordinal))
        {
            return ("Choose a location from the list.", null);
        }

        return (null, new ContactValues(phoneValue, mobileValue, officeValue));
    }

    internal static bool IsPhone(string value) =>
        value.Length <= MaxPhoneLength && value.Any(char.IsAsciiDigit) && value.All(c => char.IsAsciiDigit(c) || c is ' ' or '+' or '-' or '(' or ')' or '.');

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    /// <summary>Only the attributes whose value differs from the snapshot, with their AD names.</summary>
    public static Dictionary<string, object?> ContactChanges(ContactValues values, string? phone, string? mobile, string? office)
    {
        var changes = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (!string.Equals(values.TelephoneNumber, phone, StringComparison.Ordinal))
        {
            changes["telephoneNumber"] = values.TelephoneNumber;
        }

        if (!string.Equals(values.Mobile, mobile, StringComparison.Ordinal))
        {
            changes["mobile"] = values.Mobile;
        }

        if (!string.Equals(values.Office, office, StringComparison.Ordinal))
        {
            changes["physicalDeliveryOfficeName"] = values.Office;
        }

        return changes;
    }

    public static string ContactMessage(DirectoryWriteOutcome outcome) => outcome switch
    {
        DirectoryWriteOutcome.Success => "Your contact details have been changed.",
        DirectoryWriteOutcome.BadCurrentPassword => "Your current password is not correct.",
        DirectoryWriteOutcome.PolicyViolation => "The domain did not accept these values.",
        DirectoryWriteOutcome.Unavailable => "The domain can't be reached right now. Your details were not changed. Try again later.",
        _ => "Not allowed yet.",
    };

    public const string NothingChanged = "Nothing changed.";

    public const string SitePicturePath = "/account/site-picture";
    public const string SitePicturePanelId = "account-site-picture";

    /// <summary>Site picture uploads per user per window (no directory bind, so its own budget).</summary>
    public const int SitePictureAttempts = 10;

    public const string TooManyAttempts = "Too many attempts. Wait 15 minutes and try again.";

    /// <summary>For the audit log: the outcome as a short word, never a value.</summary>
    public static string AuditOutcome(DirectoryWriteOutcome outcome) => outcome switch
    {
        DirectoryWriteOutcome.Success => "success",
        DirectoryWriteOutcome.BadCurrentPassword => "bad current password",
        DirectoryWriteOutcome.PolicyViolation => "policy",
        DirectoryWriteOutcome.NotAllowed => "not allowed",
        DirectoryWriteOutcome.WrongAccount => "wrong account",
        DirectoryWriteOutcome.NotSecure => "not secure",
        DirectoryWriteOutcome.Unavailable => "directory unavailable",
        _ => "refused",
    };
}
