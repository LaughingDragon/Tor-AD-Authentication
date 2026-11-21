// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
// The fixes from the line-by-line security review of 0.1.0-preview, one section per review item.
using System.Reflection;
using System.Security.Claims;
using System.Reflection.Emit;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OrchardCore.DisplayManagement.Notify;
using OrchardCore.Environment.Shell.Configuration;
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
        "TimeoutSeconds=0", "TimeoutSeconds=61", "Servers=", "Servers= ", "NetBiosName=", "Domain=", "MaxSessionHours=0", "MaxSessionHours=721",
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
            case "MaxSessionHours": o.MaxSessionHours = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture); break;
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

    // ---- item 11: a failed break-glass sign-in gives the same answer as a failed directory sign-in
    private static ControllerActionDescriptor OrchardLoginPost()
    {
        // a stand-in with the name and action of Orchard's AccountController, which is all the filter looks at
        var module = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("OrchardLoginStandIn"), AssemblyBuilderAccess.Run).DefineDynamicModule("m");
        var type = module.DefineType("OrchardCore.Users.Controllers.AccountController", TypeAttributes.Public);
        type.DefineMethod("LoginPOST", MethodAttributes.Public, typeof(void), Type.EmptyTypes).GetILGenerator().Emit(OpCodes.Ret);
        var created = type.CreateType();
        return new ControllerActionDescriptor { ControllerTypeInfo = created.GetTypeInfo(), MethodInfo = created.GetMethod("LoginPOST")! };
    }

    /// <summary>Runs the filter on a login POST; Orchard's own action answers with <paramref name="orchard"/>.</summary>
    private static async Task<(ActionExecutingContext Before, ActionExecutedContext? After)> PostLoginAsync(Rig r, string userName, IActionResult orchard, string? returnUrl = null)
    {
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.0.2.20");
        http.Request.ContentType = "application/x-www-form-urlencoded";
        http.Request.Form = new FormCollection(new() { ["LoginForm.UserName"] = userName, ["LoginForm.Password"] = "Pa55-word-never-logged!" });
        if (returnUrl is not null)
        {
            http.Request.QueryString = QueryString.Create("returnUrl", returnUrl);
        }

        var action = new ActionContext(http, new RouteData(), OrchardLoginPost());
        var before = new ActionExecutingContext(action, [], new Dictionary<string, object?>(), new object());
        ActionExecutedContext? after = null;
        await r.Filter().OnActionExecutionAsync(before, () => Task.FromResult(after = new ActionExecutedContext(action, [], new object()) { Result = orchard }));
        return (before, after);
    }

    [Fact]
    public async Task A_failed_break_glass_sign_in_looks_like_a_failed_directory_sign_in()
    {
        var r = new Rig();
        r.Directory.Result = new DirectoryResult(DirectoryOutcome.BadCredentials);
        var (directory, _) = await PostLoginAsync(r, "alice", new ViewResult(), "/docs");
        var directoryMessages = r.Notifier.Messages.ToList();
        r.Notifier.Messages.Clear();

        var (_, local) = await PostLoginAsync(r, "breakglass", new ViewResult(), "/docs");

        var expected = Assert.IsType<LocalRedirectResult>(directory.Result);
        var actual = Assert.IsType<LocalRedirectResult>(local!.Result);
        Assert.Equal((expected.Url, expected.Permanent, expected.PreserveMethod), (actual.Url, actual.Permanent, actual.PreserveMethod));
        Assert.Equal(directoryMessages, r.Notifier.Messages);
    }

    [Fact]
    public async Task Orchard_raises_the_failure_event_for_a_break_glass_failure_so_Tor_does_not_raise_it_again()
    {
        var r = new Rig();

        await PostLoginAsync(r, "breakglass", new ViewResult());

        Assert.Equal(0, r.Journal.Count("LoggingInFailed"));
    }

    [Fact]
    public async Task A_good_break_glass_sign_in_and_a_two_factor_step_keep_Orchards_answer()
    {
        var r = new Rig();
        var success = new LocalRedirectResult("~/admin");
        var twoFactor = new RedirectToActionResult("LoginWithTwoFactorAuthentication", "TwoFactorAuthentication", null);

        Assert.Same(success, (await PostLoginAsync(r, "breakglass", success)).After!.Result);
        Assert.Same(twoFactor, (await PostLoginAsync(r, "breakglass", twoFactor)).After!.Result);
        Assert.Empty(r.Notifier.Messages);
    }

    // ---- item 7: an absolute session lifetime, 12 hours by default, whatever the sliding expiry does
    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 21, 8, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class SignOutRecorder : IAuthenticationService
    {
        public List<string?> SignedOut { get; } = [];

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignedOut.Add(scheme);
            return Task.CompletedTask;
        }
    }

    /// <summary>Orchard's sign-in cookie as Tor's Startup configures it, with an earlier validator (Identity's security stamp check) in place.</summary>
    private sealed class SessionRig
    {
        private readonly AuthenticationScheme _scheme = new(IdentityConstants.ApplicationScheme, null, typeof(CookieAuthenticationHandler));

        public SessionRig(Dictionary<string, string?>? settings = null)
        {
            var services = new ServiceCollection();
            services.AddSingleton<TimeProvider>(Time);
            services.AddLogging();
            services.Configure<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme, o => o.Events.OnValidatePrincipal = _ =>
            {
                InnerValidations++;
                return Task.CompletedTask;
            });
            new Startup(new ShellConfiguration(new ConfigurationBuilder().AddInMemoryCollection(settings ?? []).Build())).ConfigureServices(services);
            Options = services.BuildServiceProvider().GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(IdentityConstants.ApplicationScheme);
        }

        public ManualTime Time { get; } = new();
        public SignOutRecorder Auth { get; } = new();
        public CookieAuthenticationOptions Options { get; }
        public int InnerValidations { get; private set; }

        private DefaultHttpContext Http() => new() { RequestServices = new ServiceCollection().AddSingleton<IAuthenticationService>(Auth).BuildServiceProvider() };

        private static ClaimsPrincipal Principal() => new(new ClaimsIdentity([new Claim(ClaimTypes.Name, "alice")], "test"));

        /// <summary>A new sign-in now: the cookie's properties as the handler would write them.</summary>
        public async Task<AuthenticationProperties> SignInAsync(AuthenticationProperties? properties = null)
        {
            properties ??= new AuthenticationProperties();
            properties.IssuedUtc = Time.Now;
            await Options.Events.SigningIn(new CookieSigningInContext(Http(), _scheme, Options, Principal(), properties, new CookieOptions()));
            return properties;
        }

        /// <summary>A later request with that cookie; true when the session is still accepted.</summary>
        public async Task<bool> RequestAsync(AuthenticationProperties properties)
        {
            var context = new CookieValidatePrincipalContext(Http(), _scheme, Options, new AuthenticationTicket(Principal(), properties, _scheme.Name));
            await Options.Events.ValidatePrincipal(context);
            return context.Principal is not null;
        }
    }

    [Fact]
    public async Task A_session_ends_12_hours_after_sign_in_even_while_it_is_used()
    {
        var r = new SessionRig();
        var cookie = await r.SignInAsync();

        // used every 30 minutes: the sliding expiry renews the cookie and moves IssuedUtc each time
        for (var i = 1; i < 24; i++)
        {
            r.Time.Now += TimeSpan.FromMinutes(30);
            Assert.True(await r.RequestAsync(cookie));
            cookie.IssuedUtc = r.Time.Now;
        }

        r.Time.Now += TimeSpan.FromMinutes(30);

        Assert.False(await r.RequestAsync(cookie));
        Assert.Equal([IdentityConstants.ApplicationScheme], r.Auth.SignedOut);
    }

    [Fact]
    public async Task The_lifetime_is_configurable()
    {
        var r = new SessionRig(new() { ["Tor:MaxSessionHours"] = "2" });
        var cookie = await r.SignInAsync();

        r.Time.Now += TimeSpan.FromHours(1.9);
        Assert.True(await r.RequestAsync(cookie));
        r.Time.Now += TimeSpan.FromHours(0.2);
        Assert.False(await r.RequestAsync(cookie));
    }

    [Fact]
    public async Task A_refreshed_sign_in_keeps_the_session_start()
    {
        // Orchard's RefreshSignInAsync signs in again with the same properties: that is not a new session
        var r = new SessionRig();
        var cookie = await r.SignInAsync();
        r.Time.Now += TimeSpan.FromHours(11);
        await r.SignInAsync(cookie);
        r.Time.Now += TimeSpan.FromHours(2);

        Assert.False(await r.RequestAsync(cookie));
    }

    [Fact]
    public async Task A_cookie_from_before_the_upgrade_counts_from_when_it_was_issued_and_the_earlier_validator_still_runs()
    {
        var r = new SessionRig();
        var old = new AuthenticationProperties { IssuedUtc = r.Time.Now - TimeSpan.FromHours(13) };
        var recent = new AuthenticationProperties { IssuedUtc = r.Time.Now - TimeSpan.FromHours(1) };

        Assert.False(await r.RequestAsync(old));
        Assert.True(await r.RequestAsync(recent));
        Assert.Equal(1, r.InnerValidations);
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
