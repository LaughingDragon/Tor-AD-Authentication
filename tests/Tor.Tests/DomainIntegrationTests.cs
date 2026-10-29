// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// Against the real domain, with spare test accounts.
//
// The passwords live in Windows Credential Manager of the account running the tests, stored by the
// domain owner (never typed here, never printed, never written anywhere):
//   cmdkey /generic:Tor-Test-Member   /user:<name of the test user in Intranet-Users> /pass
//   cmdkey /generic:Tor-Test-Outsider /user:<name of the test user in no group>      /pass
// The domain and domain controller come from this machine's own domain membership.
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Tor.Directory;
using Xunit;

namespace Tor.Tests;

public class DomainIntegrationTests
{
    private static DirectoryAuthenticator Authenticator(bool ldaps = true) => new(
        Options.Create(new TorOptions
        {
            Domain = TestDomain.DnsName,
            NetBiosName = TestDomain.NetBiosName,
            Servers = [TestDomain.Server],
            UseLdaps = ldaps,
            GroupRoles = new(StringComparer.OrdinalIgnoreCase) { ["Intranet-Users"] = "Intranet Users" },
        }),
        NullLogger<DirectoryAuthenticator>.Instance);

    [DomainFact("Tor-Test-Member")]
    public void Member_signs_in_with_groups_sid_and_ldaps()
    {
        var (user, password) = StoredCredential.Read("Tor-Test-Member")!.Value;

        var result = Authenticator().Authenticate(AccountName.Parse(user, TestDomain.NetBiosName, TestDomain.DnsName)!, password);

        Assert.Equal(DirectoryOutcome.Success, result.Outcome);
        Assert.StartsWith("S-1-5-21-", result.Sid);
        Assert.Contains("Intranet-Users", result.Groups!, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(["Intranet Users"], new RoleMapper(new Dictionary<string, string> { ["Intranet-Users"] = "Intranet Users" }).RolesFor(result.Groups!));
        Assert.StartsWith("LDAPS", result.Transport);
    }

    [DomainFact("Tor-Test-Member")]
    public void Member_signs_in_over_signed_and_sealed_ldap()
    {
        var (user, password) = StoredCredential.Read("Tor-Test-Member")!.Value;

        var result = Authenticator(ldaps: false).Authenticate(AccountName.Parse(user, TestDomain.NetBiosName, TestDomain.DnsName)!, password);

        Assert.Equal(DirectoryOutcome.Success, result.Outcome);
    }

    [DomainFact("Tor-Test-Member")]
    public void Member_signs_in_by_upn_and_down_level_name()
    {
        var (user, password) = StoredCredential.Read("Tor-Test-Member")!.Value;
        var bare = user.Contains('\\') ? user[(user.IndexOf('\\') + 1)..] : user.Split('@')[0];

        foreach (var typed in new[] { $@"{TestDomain.NetBiosName}\{bare}", $"{bare}@{TestDomain.DnsName}" })
        {
            var result = Authenticator().Authenticate(AccountName.Parse(typed, TestDomain.NetBiosName, TestDomain.DnsName)!, password);
            Assert.Equal(DirectoryOutcome.Success, result.Outcome);
        }
    }

    [DomainFact("Tor-Test-Member")]
    public void Wrong_password_is_bad_credentials()
    {
        // one failed bind against the test account; keep this the only one per run (AD lockout)
        var (user, password) = StoredCredential.Read("Tor-Test-Member")!.Value;

        var result = Authenticator().Authenticate(AccountName.Parse(user, TestDomain.NetBiosName, TestDomain.DnsName)!, password + "-wrong");

        Assert.Equal(DirectoryOutcome.BadCredentials, result.Outcome);
    }

    [DomainFact("Tor-Test-Outsider")]
    public void Outsider_binds_but_fails_the_gate()
    {
        var (user, password) = StoredCredential.Read("Tor-Test-Outsider")!.Value;

        var result = Authenticator().Authenticate(AccountName.Parse(user, TestDomain.NetBiosName, TestDomain.DnsName)!, password);

        Assert.Equal(DirectoryOutcome.Success, result.Outcome);
        Assert.False(new RoleMapper(new Dictionary<string, string> { ["Intranet-Users"] = "Intranet Users" }).IsAllowed(result.Groups!));
    }
}

/// <summary>Skips the test unless the named credential is stored and this machine is in a domain.</summary>
public sealed class DomainFactAttribute : FactAttribute
{
    public DomainFactAttribute(string credentialTarget)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(TestDomain.DnsName) || string.IsNullOrEmpty(TestDomain.Server))
        {
            Skip = "not on a domain-joined Windows machine";
        }
        else if (StoredCredential.Read(credentialTarget) is null)
        {
            Skip = $"credential {credentialTarget} not stored (see the file header)";
        }
    }
}

internal static class TestDomain
{
    public static string DnsName { get; } = IPGlobalProperties.GetIPGlobalProperties().DomainName;

    public static string NetBiosName { get; } = Environment.GetEnvironmentVariable("USERDOMAIN") ?? "";

    // the DC that logged this session on, as a full name (the LDAPS certificate names the DC, not the domain)
    public static string Server { get; } = Environment.GetEnvironmentVariable("LOGONSERVER") is { Length: > 2 } logon
        ? $"{logon.TrimStart('\\')}.{IPGlobalProperties.GetIPGlobalProperties().DomainName}"
        : "";
}

/// <summary>Reads a generic credential from Windows Credential Manager. The value is never printed.</summary>
internal static class StoredCredential
{
    public static (string User, string Password)? Read(string target)
    {
        if (!OperatingSystem.IsWindows() || !CredRead(target, 1, 0, out var handle))
        {
            return null;
        }

        try
        {
            var credential = Marshal.PtrToStructure<Credential>(handle);
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0 || credential.UserName is null)
            {
                return null;
            }

            return (credential.UserName, Marshal.PtrToStringUni(credential.CredentialBlob, (int)credential.CredentialBlobSize / 2));
        }
        finally
        {
            CredFree(handle);
        }
    }

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, int type, int flags, out IntPtr credential);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
}
