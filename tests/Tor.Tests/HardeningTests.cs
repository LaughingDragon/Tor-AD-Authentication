// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// The fixes from the line-by-line security review of 0.1.0-preview, one section per review item.
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using OrchardCore.DisplayManagement.Notify;
using OrchardCore.Modules.Manifest;
using Tor.Account;
using Tor.Controllers;
using Tor.Directory;
using Tor.Filters;
using Tor.Services;
using Xunit;

namespace Tor.Tests;

public class HardeningTests
{
    // ---- item 23: one version everywhere
    [Fact]
    public void The_manifest_version_is_the_package_version()
    {
        var assembly = typeof(Startup).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        var package = informational.Split('+')[0];

        var module = assembly.GetCustomAttributes<ModuleAttribute>().Single(m => m.GetType() == typeof(ModuleAttribute) && m.Name == "Tor");
        Assert.Equal(package, module.Version);
    }

    // ---- item 19: nothing from /account is stored by a browser or a proxy
    [Fact]
    public void Every_account_response_is_private_and_never_stored()
    {
        var http = new DefaultHttpContext();
        http.Response.Headers.CacheControl = "private, no-cache"; // what the picture actions set before
        var action = new ActionContext(http, new RouteData(), new ActionDescriptor());
        var context = new ResultExecutingContext(action, [], new OkResult(), new object());

        foreach (var filter in typeof(AccountController).GetCustomAttributes(inherit: true).OfType<IResultFilter>())
        {
            filter.OnResultExecuting(context);
        }

        Assert.Equal("private, no-store", http.Response.Headers.CacheControl.ToString());
    }

    // ---- item 2: the login password is bounded before the throttle and the bind
    [Fact]
    public async Task A_login_password_over_256_characters_never_reaches_the_directory_and_counts_as_a_failure()
    {
        var r = new Rig();

        var result = await r.SignInAsync(password: new string('x', 257));

        Assert.Equal(0, r.Journal.Count("bind"));
        Assert.Equal("~/Login", Assert.IsType<LocalRedirectResult>(result).Url);
        Assert.Equal([(NotifyType.Error, "Invalid login attempt.")], r.Notifier.Messages);
        Assert.Equal(1, r.Journal.Count("LoggingInFailed"));

        for (var i = 1; i < r.Options.MaxFailuresPerUser; i++)
        {
            await r.SignInAsync(password: new string('x', 1_000_000));
        }

        Assert.True(r.Throttle.IsBlocked("alice", "198.51.100.99"));
    }

    [Fact]
    public async Task A_login_password_of_256_characters_still_binds()
    {
        var r = new Rig();

        await r.SignInAsync(password: new string('x', 256));

        Assert.Equal(256, Assert.Single(r.Directory.Passwords).Length);
    }

    // ---- item 8: the return address follows ASP.NET Core's own local-URL rule
    [Theory]
    [InlineData("~//evil.example")]
    [InlineData("~/\\evil.example")]
    [InlineData("/\t/evil.example")]
    [InlineData("/docs\r\nX")]
    [InlineData("~/docs\u0000")]
    public async Task Return_addresses_ASP_NET_refuses_send_the_user_to_the_site_root(string returnUrl)
    {
        Assert.False(DirectoryLoginFilter.IsLocalUrl(returnUrl));
        Assert.Equal("~/", Assert.IsType<LocalRedirectResult>(await new Rig().SignInAsync(returnUrl: returnUrl)).Url);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/docs?page=2")]
    [InlineData("~/")]
    [InlineData("~/docs")]
    public void Local_return_addresses_are_still_used(string returnUrl) => Assert.True(DirectoryLoginFilter.IsLocalUrl(returnUrl));

    [Theory]
    [InlineData("")]
    [InlineData("/")]
    [InlineData("~")]
    [InlineData("~/")]
    [InlineData("//evil.example")]
    [InlineData("/\\evil.example")]
    [InlineData("~//evil.example")]
    [InlineData("~/\\evil.example")]
    [InlineData("http://evil.example")]
    [InlineData("javascript:alert(1)")]
    [InlineData("/%2F%2Fevil.example")]
    [InlineData("/a\u007fb")]
    [InlineData("/a\u0085b")]
    [InlineData(" /docs")]
    public void Tor_and_ASP_NET_agree_on_what_is_local(string url)
    {
        var aspNet = new UrlHelper(new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor())).IsLocalUrl(url);

        Assert.Equal(aspNet, DirectoryLoginFilter.IsLocalUrl(url));
    }

    // ---- item 12: no Unicode line separators or invisible format characters in logged names
    [Theory]
    [InlineData("a\u2028b", "ab")]
    [InlineData("a\u2029b", "ab")]
    [InlineData("admin\u202Egnp.exe", "admingnp.exe")]
    [InlineData("al\u200Bice", "alice")]
    [InlineData("\uFEFFalice", "alice")]
    [InlineData("a\u2066b\u2069", "ab")]
    public void Separators_and_format_characters_are_removed_from_logged_names(string typed, string logged) =>
        Assert.Equal(logged, SignInAudit.Clean(typed));

    [Theory]
    [InlineData("José Müller")]
    [InlineData("Łukasz")]
    [InlineData("名前")]
    [InlineData("alice \U0001F600")]
    public void Ordinary_letters_and_symbols_are_kept(string typed) => Assert.Equal(typed, SignInAudit.Clean(typed));

    // ---- item 14: options are checked, and a bad configuration fails closed
    public static TheoryData<string> BadSettings() =>
    [
        "FailureWindowMinutes=0", "FailureWindowMinutes=-5", "MaxFailuresPerUser=0", "MaxFailuresPerClient=-1",
        "TimeoutSeconds=0", "TimeoutSeconds=61", "Servers=", "Servers= ", "NetBiosName=", "Domain=",
    ];

    private static TorOptions With(string setting)
    {
        var o = new TorOptions { Domain = "corp.example.com", NetBiosName = "CORP", Servers = ["dc.invalid"], LocalAccounts = ["breakglass"] };
        var (name, value) = (setting.Split('=')[0], setting.Split('=')[1]);
        switch (name)
        {
            case "FailureWindowMinutes": o.FailureWindowMinutes = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture); break;
            case "MaxFailuresPerUser": o.MaxFailuresPerUser = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture); break;
            case "MaxFailuresPerClient": o.MaxFailuresPerClient = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture); break;
            case "TimeoutSeconds": o.TimeoutSeconds = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture); break;
            case "Servers": o.Servers = value.Length == 0 ? [] : [value]; break;
            case "NetBiosName": o.NetBiosName = value; break;
            case "Domain": o.Domain = value; break;
        }

        return o;
    }

    [Theory]
    [MemberData(nameof(BadSettings))]
    public async Task A_bad_setting_refuses_every_directory_sign_in_without_contacting_the_domain(string setting)
    {
        var r = new Rig(With(setting));

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal("~/Login", Assert.IsType<LocalRedirectResult>(await r.SignInAsync()).Url);
        }

        Assert.Equal(0, r.Journal.Count("bind"));
        Assert.Equal(3, r.Journal.Count("LoggingInFailed"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void A_zero_or_negative_window_does_not_switch_the_throttle_off(int minutes)
    {
        var throttle = new LoginThrottle(Microsoft.Extensions.Options.Options.Create(With("FailureWindowMinutes=" + minutes)), TimeProvider.System);

        for (var i = 0; i < 5; i++)
        {
            throttle.RecordFailure("local:breakglass", "192.0.2.1");
        }

        Assert.True(throttle.IsBlocked("local:breakglass", "192.0.2.2"));
    }

    [Fact]
    public async Task Problems_are_logged_once_at_tenant_start_and_plain_LDAP_is_warned()
    {
        var bad = With("Servers=");
        bad.UseLdaps = false;
        var log = new ListLogger();

        await new RoleMappingLog(RoleMapper.From(bad), Microsoft.Extensions.Options.Options.Create(bad), log).ActivatedAsync();

        Assert.Contains(log.Messages, m => m.Contains("Servers", StringComparison.Ordinal) && m.Contains("every directory sign-in is refused", StringComparison.Ordinal));
        Assert.Contains(log.Messages, m => m.Contains("UseLdaps is false", StringComparison.Ordinal));
        Assert.Empty(TorOptionsCheck.Problems(With("Domain=corp.example.com")));
    }

    // ---- item 6: at most 16 million pixels (about 64 MB decoded), checked from the header before decoding
    [Theory]
    [InlineData(5_000, 4_000)]
    [InlineData(8_000, 5_000)]
    [InlineData(12_000, 1_400)]
    public void A_picture_over_16_million_pixels_is_refused_before_decoding(int width, int height) =>
        Assert.Equal(PictureOutcome.TooManyPixels, PictureProcessor.Process(PictureTests.PngWithHeaderSize(width, height)).Outcome);

    [Theory]
    [InlineData(4_000, 4_000)]
    [InlineData(12_000, 1_333)]
    public void A_picture_of_16_million_pixels_or_fewer_gets_past_the_size_check(int width, int height) =>
        Assert.NotEqual(PictureOutcome.TooManyPixels, PictureProcessor.Process(PictureTests.PngWithHeaderSize(width, height)).Outcome);

    // ---- item 9: the throttle counts one person once, is bounded, and checks and counts in one step
    [Fact]
    public async Task The_plain_name_and_the_user_principal_name_share_one_count()
    {
        var r = new Rig();
        r.Directory.Result = new DirectoryResult(DirectoryOutcome.BadCredentials);

        foreach (var name in new[] { "alice", "alice@corp.example.com", "CORP\alice", "ALICE@CORP.EXAMPLE.COM" })
        {
            for (var i = 0; i < 3; i++)
            {
                await r.SignInAsync(name, client: $"192.0.2.{r.Journal.Entries.Count}");
            }
        }

        Assert.Equal(r.Options.MaxFailuresPerUser, r.Journal.Count("bind"));
    }

    [Fact]
    public void A_user_principal_name_of_another_suffix_keeps_its_own_count()
    {
        Assert.Equal("alice", AccountName.Parse("alice@corp.example.com", "CORP", "corp.example.com")!.ThrottleKey);
        Assert.Equal("alice@partner.example", AccountName.Parse("alice@partner.example", "CORP", "corp.example.com")!.ThrottleKey);
    }

    private sealed class SlowDirectory : IDirectoryAuthenticator
    {
        private int _calls;

        public int Calls => _calls;

        public DirectoryResult Authenticate(AccountName account, string password)
        {
            Interlocked.Increment(ref _calls);
            Thread.Sleep(50);
            return new DirectoryResult(DirectoryOutcome.BadCredentials);
        }
    }

    [Fact]
    public async Task Parallel_attempts_cannot_pass_the_limit()
    {
        var slow = new SlowDirectory();
        var r = new Rig { Authenticator = slow };

        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() => r.SignInAsync(client: "192.0.2." + i))));

        Assert.Equal(r.Options.MaxFailuresPerUser, slow.Calls);
    }

    private static System.Collections.ICollection Table(LoginThrottle throttle) =>
        (System.Collections.ICollection)typeof(LoginThrottle).GetField("_failures", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(throttle)!;

    // the earlier throttle scanned the whole table on every failure once it held 10,000 entries: the timeout catches that
    [Fact(Timeout = 60_000)]
    public async Task The_table_has_a_hard_cap_while_windows_are_live_and_stays_fast()
    {
        var throttle = new LoginThrottle(Microsoft.Extensions.Options.Options.Create(new TorOptions()), TimeProvider.System);

        await Task.Run(() =>
        {
            for (var i = 0; i < 60_000; i++)
            {
                throttle.RecordFailure("user" + i, "client" + i);
            }
        });

        Assert.InRange(Table(throttle).Count, 1, 50_000);
    }

    [Fact]
    public void Keys_are_bounded_whatever_was_typed()
    {
        var throttle = new LoginThrottle(Microsoft.Extensions.Options.Options.Create(new TorOptions()), TimeProvider.System);

        throttle.RecordFailure(new string('x', 100_000), new string('y', 10_000));

        var keys = ((System.Collections.IDictionary)Table(throttle)).Keys.Cast<string>().ToList();
        Assert.Equal(2, keys.Count);
        Assert.All(keys, k => Assert.InRange(k.Length, 1, 80));
        Assert.True(throttle.IsBlocked(new string('x', 100_000), "z") == false);
    }

    [Fact]
    public async Task A_good_sign_in_gives_the_client_address_its_attempt_back()
    {
        var r = new Rig();
        for (var i = 0; i < r.Options.MaxFailuresPerClient - 1; i++)
        {
            r.Throttle.RecordFailure("user" + i, "192.0.2.10");
        }

        await r.SignInAsync();

        Assert.False(r.Throttle.IsBlocked("bob", "192.0.2.10"));
    }

    /// <summary>A directory sign-in with stand-ins, as in <see cref="LoginFilterTests"/>.</summary>
    private sealed class Rig
    {
        public Journal Journal { get; } = new();
        public FakeDirectory Directory { get; }
        public FakeSync Sync { get; }
        public FakeOrchard Orchard { get; }
        public RecordingLoginEvents Events { get; }
        public FakeNotifier Notifier { get; } = new();
        public ListLogger Log { get; } = new();
        public LoginThrottle Throttle { get; }
        public TorOptions Options { get; }
        public IDirectoryAuthenticator? Authenticator { get; init; }

        public Rig(TorOptions? options = null)
        {
            Options = options ?? new() { Domain = "corp.example.com", NetBiosName = "CORP", Servers = ["dc.invalid"], LocalAccounts = ["breakglass"] };
            Directory = new FakeDirectory(Journal);
            Sync = new FakeSync(Journal);
            Orchard = new FakeOrchard(Journal);
            Events = new RecordingLoginEvents(Journal);
            Throttle = new LoginThrottle(Microsoft.Extensions.Options.Options.Create(Options), TimeProvider.System);
        }

        public DirectoryLoginFilter Filter() => new(
            Microsoft.Extensions.Options.Options.Create(Options),
            Authenticator ?? Directory,
            Sync,
            Throttle,
            new SignInAudit(Log),
            Orchard,
            [Events],
            [],
            new ListLogger<DirectoryLoginFilter>(Log),
            Notifier,
            new FakeLocalizer<DirectoryLoginFilter>());

        public Task<IActionResult> SignInAsync(string userName = "alice", string password = "Pa55-word-never-logged!", string client = "192.0.2.10", string? returnUrl = null) =>
            Filter().SignInDirectoryAsync(userName, password, client, returnUrl);
    }
}
