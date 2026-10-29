// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Tor.Directory;

public enum DirectoryOutcome
{
    Success,
    BadCredentials,
    AccountDisabled,
    AccountLocked,
    AccountExpired,
    PasswordExpired,
    NotFound,
    Unavailable,
}

/// <summary>What one bind told us. Account details are only set on Success.</summary>
public sealed record DirectoryResult(
    DirectoryOutcome Outcome,
    string? Sid = null,
    string? SamAccountName = null,
    string? UserPrincipalName = null,
    string? DisplayName = null,
    string? Mail = null,
    IReadOnlyList<string>? Groups = null,
    string? Transport = null,
    DirectorySnapshot? Snapshot = null);

public interface IDirectoryAuthenticator
{
    DirectoryResult Authenticate(AccountName account, string password);
}

/// <summary>
/// Binds to the domain as the user (Negotiate; LDAPS, or LDAP with signing and sealing) and reads the
/// user's own object and tokenGroups with that bind. No service account, nothing stored.
/// </summary>
public sealed partial class DirectoryAuthenticator : IDirectoryAuthenticator
{
    private const string WhoAmIOid = "1.3.6.1.4.1.4203.1.11.3";
    private const int UacAccountDisable = 0x2;
    private const int UacComputedLockout = 0x10;
    private const int UacComputedPasswordExpired = 0x800000;

    private readonly TorOptions _options;
    private readonly ILogger _logger;
    private readonly RoleMapper _roleMapper;

    public DirectoryAuthenticator(IOptions<TorOptions> options, ILogger<DirectoryAuthenticator> logger, RoleMapper? roleMapper = null)
    {
        _options = options.Value;
        _logger = logger;
        _roleMapper = roleMapper ?? RoleMapper.From(_options);
    }

    public string Transport => _options.UseLdaps ? "LDAPS 636, Negotiate" : "LDAP 389, Negotiate signed and sealed";

    public DirectoryResult Authenticate(AccountName account, string password)
    {
        if (_options.Servers.Length == 0 || string.IsNullOrEmpty(_options.NetBiosName))
        {
            _logger.LogError("Tor is not configured: Tor:Servers and Tor:NetBiosName are required.");
            return new DirectoryResult(DirectoryOutcome.Unavailable);
        }

        if (string.IsNullOrEmpty(password))
        {
            return new DirectoryResult(DirectoryOutcome.BadCredentials);
        }

        using var connection = Open(_options, account, password);

        try
        {
            connection.Bind();
        }
        catch (LdapException ex)
        {
            return new DirectoryResult(ClassifyBindFailure(ex));
        }

        try
        {
            return ReadAccount(connection);
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException)
        {
            _logger.LogWarning("Tor: bind succeeded but the account could not be read ({Error}).", ex.GetType().Name);
            return new DirectoryResult(DirectoryOutcome.NotFound);
        }
    }

    /// <summary>A connection that binds as the user: Negotiate over LDAPS, or LDAP with signing and sealing.</summary>
    internal static LdapConnection Open(TorOptions options, AccountName account, string password)
    {
        var credential = account.Kind == AccountNameKind.UserPrincipalName
            ? new NetworkCredential(account.BindName, password)
            : new NetworkCredential(account.Name, password, options.NetBiosName);

        var identifier = new LdapDirectoryIdentifier(options.Servers, options.UseLdaps ? 636 : 389, fullyQualifiedDnsHostName: true, connectionless: false);
        var connection = new LdapConnection(identifier, credential, AuthType.Negotiate)
        {
            Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds),
        };

        var session = connection.SessionOptions;
        session.ProtocolVersion = 3;
        session.ReferralChasing = ReferralChasingOptions.None;
        if (options.UseLdaps)
        {
            // TLS protects the bind; Negotiate sealing on top of TLS is refused by Windows
            session.SecureSocketLayer = true;
        }
        else
        {
            session.Signing = true;
            session.Sealing = true;
        }

        return connection;
    }

    /// <summary>The bound user's own entry, read by WhoAmI then sAMAccountName, or null.</summary>
    internal static (string NamingContext, string DistinguishedName)? FindSelf(LdapConnection connection)
    {
        // who the bind really is, as DOMAIN\sAMAccountName
        var whoAmI = (ExtendedResponse)connection.SendRequest(new ExtendedRequest(WhoAmIOid));
        var identity = whoAmI.ResponseValue is { Length: > 0 } value ? Encoding.UTF8.GetString(value) : "";
        var sam = identity.StartsWith("u:", StringComparison.Ordinal) && identity.Contains('\\') ? identity[(identity.IndexOf('\\') + 1)..] : null;
        if (string.IsNullOrEmpty(sam))
        {
            return null;
        }

        var namingContext = ReadSingle(connection, "", "(objectClass=*)", "defaultNamingContext");
        if (namingContext is null)
        {
            return null;
        }

        var found = (SearchResponse)connection.SendRequest(new SearchRequest(
            namingContext,
            $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={Escape(sam)}))",
            SearchScope.Subtree,
            "distinguishedName"));

        return found.Entries.Count == 1 ? (namingContext, found.Entries[0].DistinguishedName) : null;
    }

    private DirectoryResult ReadAccount(LdapConnection connection)
    {
        if (FindSelf(connection) is not var (namingContext, distinguishedName))
        {
            return new DirectoryResult(DirectoryOutcome.NotFound);
        }

        // tokenGroups and the computed attributes are only returned on a base search of the object itself
        var user = ((SearchResponse)connection.SendRequest(new SearchRequest(
            distinguishedName,
            "(objectClass=user)",
            SearchScope.Base,
            [.. AccountAttributes, .. SnapshotAttributes]))).Entries[0];

        return Evaluate(user, ManagedGroupsOf(connection, namingContext, user), ManagedComputersOf(connection, namingContext, distinguishedName));
    }

    internal static readonly string[] AccountAttributes =
    [
        "objectSid", "sAMAccountName", "userPrincipalName", "displayName", "mail", "userAccountControl",
        "msDS-User-Account-Control-Computed", "accountExpires", "tokenGroups",
    ];

    // the allow-list of what the snapshot reads
    internal static readonly string[] SnapshotAttributes =
    [
        "title", "department", "description", "telephoneNumber", "mobile", "physicalDeliveryOfficeName",
        "whenCreated", "pwdLastSet", "msDS-UserPasswordExpiryTimeComputed", "lastLogonTimestamp", "homeDirectory", "thumbnailPhoto",
    ];

    internal DirectoryResult Evaluate(SearchResultEntry user, List<string> groups, List<string> computers)
    {
        var uac = ReadInt(user, "userAccountControl");
        var computed = ReadInt(user, "msDS-User-Account-Control-Computed");
        if ((uac & UacAccountDisable) != 0)
        {
            return new DirectoryResult(DirectoryOutcome.AccountDisabled);
        }

        if ((computed & UacComputedLockout) != 0)
        {
            return new DirectoryResult(DirectoryOutcome.AccountLocked);
        }

        if ((computed & UacComputedPasswordExpired) != 0)
        {
            return new DirectoryResult(DirectoryOutcome.PasswordExpired);
        }

        if (IsExpired(ReadString(user, "accountExpires")))
        {
            return new DirectoryResult(DirectoryOutcome.AccountExpired);
        }

        var sid = user.Attributes["objectSid"]?.GetValues(typeof(byte[])) is [byte[] sidBytes, ..] ? Sid.ToText(sidBytes) : null;
        if (sid is null)
        {
            return new DirectoryResult(DirectoryOutcome.NotFound);
        }

        var snapshot = Snapshot(user, uac, groups, computers);
        return new DirectoryResult(
            DirectoryOutcome.Success,
            sid,
            ReadString(user, "sAMAccountName"),
            snapshot.UserPrincipalName,
            snapshot.DisplayName,
            snapshot.Mail,
            groups,
            Transport,
            snapshot);
    }

    internal static DirectorySnapshot Snapshot(SearchResultEntry user, int uac, IEnumerable<string> groups, IEnumerable<string> computers)
    {
        var photo = user.Attributes["thumbnailPhoto"]?.GetValues(typeof(byte[])) is [byte[] bytes, ..] ? bytes : null;
        var photoType = photo is { Length: > 0 and <= DirectorySnapshot.MaxPhotoBytes } ? DirectorySnapshot.ImageType(photo) : null;

        return new DirectorySnapshot
        {
            DisplayName = DirectorySnapshot.Cap(ReadString(user, "displayName")),
            Mail = DirectorySnapshot.LowerDomain(ReadString(user, "mail")),
            UserPrincipalName = DirectorySnapshot.LowerDomain(ReadString(user, "userPrincipalName")),
            Title = DirectorySnapshot.Cap(ReadString(user, "title")),
            Department = DirectorySnapshot.Cap(ReadString(user, "department")),
            Description = DirectorySnapshot.Cap(ReadString(user, "description"), DirectorySnapshot.MaxDescription),
            TelephoneNumber = DirectorySnapshot.Cap(ReadString(user, "telephoneNumber")),
            Mobile = DirectorySnapshot.Cap(ReadString(user, "mobile")),
            Office = DirectorySnapshot.Cap(ReadString(user, "physicalDeliveryOfficeName")),
            WhenCreatedUtc = DirectorySnapshot.FromGeneralizedTime(ReadString(user, "whenCreated")),
            PasswordLastSetUtc = DirectorySnapshot.FromFileTime(ReadString(user, "pwdLastSet")),
            PasswordExpiresUtc = DirectorySnapshot.FromFileTime(ReadString(user, "msDS-UserPasswordExpiryTimeComputed")),
            LastLogonUtc = DirectorySnapshot.FromFileTime(ReadString(user, "lastLogonTimestamp")),
            AccountExpiresUtc = DirectorySnapshot.FromFileTime(ReadString(user, "accountExpires")),
            Enabled = (uac & UacAccountDisable) == 0,
            HomeDirectory = DirectorySnapshot.Cap(ReadString(user, "homeDirectory")),
            Groups = DirectorySnapshot.CapList(groups),
            ManagedComputers = DirectorySnapshot.CapList(computers),
            Photo = photoType is null ? null : photo,
            PhotoContentType = photoType,
        };
    }

    // computers whose managedBy is this user (read with the user's own bind)
    private static List<string> ManagedComputersOf(LdapConnection connection, string namingContext, string distinguishedName)
    {
        var request = new SearchRequest(
            namingContext,
            $"(&(objectCategory=computer)(managedBy={Escape(distinguishedName)}))",
            SearchScope.Subtree,
            "name", "dNSHostName")
        {
            SizeLimit = DirectorySnapshot.MaxListItems,
        };

        try
        {
            var response = (SearchResponse)connection.SendRequest(request);
            return response.Entries.Cast<SearchResultEntry>()
                .Select(e => ReadString(e, "dNSHostName") ?? ReadString(e, "name"))
                .OfType<string>()
                .ToList();
        }
        catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.SizeLimitExceeded && ex.Response is SearchResponse partial)
        {
            return partial.Entries.Cast<SearchResultEntry>()
                .Select(e => ReadString(e, "dNSHostName") ?? ReadString(e, "name"))
                .OfType<string>()
                .ToList();
        }
    }

    // the managed groups the user is in, directly or nested: tokenGroups SIDs against the managed groups' SIDs
    private List<string> ManagedGroupsOf(LdapConnection connection, string namingContext, SearchResultEntry user)
    {
        var tokenSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (user.Attributes["tokenGroups"] is { } tokenGroups)
        {
            foreach (var value in tokenGroups.GetValues(typeof(byte[])))
            {
                if (Sid.ToText((byte[])value) is { } text)
                {
                    tokenSids.Add(text);
                }
            }
        }

        // only the effective mapping: refused entries (e.g. Administrator without the flag) are not even looked up
        var names = string.Concat(_roleMapper.ManagedGroups.Select(g => $"(sAMAccountName={Escape(g)})"));
        if (names.Length == 0)
        {
            return [];
        }

        var groups = (SearchResponse)connection.SendRequest(new SearchRequest(
            namingContext, $"(&(objectClass=group)(|{names}))", SearchScope.Subtree, "sAMAccountName", "objectSid"));

        var member = new List<string>();
        foreach (SearchResultEntry group in groups.Entries)
        {
            var groupSid = group.Attributes["objectSid"]?.GetValues(typeof(byte[])) is [byte[] bytes, ..] ? Sid.ToText(bytes) : null;
            if (groupSid is not null && tokenSids.Contains(groupSid) && ReadString(group, "sAMAccountName") is { } name)
            {
                member.Add(name);
            }
        }

        return member;
    }

    // AD puts the reason in the bind error text as "data 52e" and similar
    internal static DirectoryOutcome ClassifyBindFailure(LdapException ex)
    {
        if (ex.ErrorCode != 49)
        {
            return DirectoryOutcome.Unavailable;
        }

        var text = ex.ServerErrorMessage ?? "";
        return text switch
        {
            _ when text.Contains("data 533", StringComparison.OrdinalIgnoreCase) => DirectoryOutcome.AccountDisabled,
            _ when text.Contains("data 775", StringComparison.OrdinalIgnoreCase) => DirectoryOutcome.AccountLocked,
            _ when text.Contains("data 701", StringComparison.OrdinalIgnoreCase) => DirectoryOutcome.AccountExpired,
            _ when text.Contains("data 532", StringComparison.OrdinalIgnoreCase) ||
                   text.Contains("data 773", StringComparison.OrdinalIgnoreCase) => DirectoryOutcome.PasswordExpired,
            _ => DirectoryOutcome.BadCredentials,
        };
    }

    // accountExpires: 100 ns ticks since 1601 UTC; 0 and Int64.MaxValue mean never
    internal static bool IsExpired(string? accountExpires, DateTimeOffset? now = null)
    {
        if (!long.TryParse(accountExpires, out var ticks) || ticks <= 0 || ticks == long.MaxValue)
        {
            return false;
        }

        try
        {
            return DateTimeOffset.FromFileTime(ticks) <= (now ?? DateTimeOffset.UtcNow);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    // RFC 4515 filter escaping
    internal static string Escape(string value)
    {
        var text = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            text.Append(ch switch
            {
                '\\' => @"\5c",
                '*' => @"\2a",
                '(' => @"\28",
                ')' => @"\29",
                '\0' => @"\00",
                _ => ch.ToString(),
            });
        }

        return text.ToString();
    }

    private static string? ReadSingle(LdapConnection connection, string baseDn, string filter, string attribute)
    {
        var response = (SearchResponse)connection.SendRequest(new SearchRequest(baseDn, filter, SearchScope.Base, attribute));
        return response.Entries.Count == 1 ? ReadString(response.Entries[0], attribute) : null;
    }

    private static string? ReadString(SearchResultEntry entry, string attribute) =>
        entry.Attributes[attribute]?.GetValues(typeof(string)) is [string value, ..] && value.Length > 0 ? value : null;

    private static int ReadInt(SearchResultEntry entry, string attribute) =>
        int.TryParse(ReadString(entry, attribute), out var value) ? value : 0;
}
