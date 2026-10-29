// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Localization;
using Microsoft.Extensions.Options;
using OrchardCore.DisplayManagement;
using OrchardCore.DisplayManagement.ModelBinding;
using OrchardCore.DisplayManagement.Notify;
using OrchardCore.Users;
using OrchardCore.Users.Models;
using Tor.Account;
using Tor.Directory;
using Tor.Services;

namespace Tor.Controllers;

/// <summary>
/// /account: the signed-in user's own account. There is no user id in any route or form; every action
/// works on the signed-in user, and the directory ones on the SID linked to that user.
/// Forms post here and come back to /account (post, redirect, get), so no typed value is ever rendered.
/// </summary>
[Authorize]
[Route("account")]
public sealed class AccountController : Controller
{
    private readonly IAuthorizationService _authorizationService;
    private readonly UserManager<IUser> _userManager;
    private readonly IDisplayManager<AccountPage> _displayManager;
    private readonly IUpdateModelAccessor _updateModelAccessor;
    private readonly IDirectoryWriter _writer;
    private readonly SnapshotStore _snapshots;
    private readonly SitePictureStore _sitePictures;
    private readonly IAccountActionRecorder _recorder;
    private readonly ActionLimiter _limiter;
    private readonly SignInAudit _audit;
    private readonly INotifier _notifier;
    private readonly TorOptions _options;
    private readonly IHtmlLocalizer H;

    public AccountController(
        IAuthorizationService authorizationService,
        UserManager<IUser> userManager,
        IDisplayManager<AccountPage> displayManager,
        IUpdateModelAccessor updateModelAccessor,
        IDirectoryWriter writer,
        SnapshotStore snapshots,
        SitePictureStore sitePictures,
        IAccountActionRecorder recorder,
        ActionLimiter limiter,
        SignInAudit audit,
        INotifier notifier,
        IOptions<TorOptions> options,
        IHtmlLocalizer<AccountController> localizer)
    {
        _authorizationService = authorizationService;
        _userManager = userManager;
        _displayManager = displayManager;
        _updateModelAccessor = updateModelAccessor;
        _writer = writer;
        _snapshots = snapshots;
        _sitePictures = sitePictures;
        _recorder = recorder;
        _limiter = limiter;
        _audit = audit;
        _notifier = notifier;
        _options = options.Value;
        H = localizer;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index()
    {
        if (!await _authorizationService.AuthorizeAsync(User, AccountPermissions.ViewOwnAccount) ||
            await CurrentAsync() is not { } current)
        {
            return Forbid();
        }

        var shape = await _displayManager.BuildDisplayAsync(current.Page, _updateModelAccessor.ModelUpdater);
        return View(shape);
    }

    /// <summary>The signed-in user's own domain picture from the snapshot; private to that user's browser.</summary>
    [HttpGet("picture")]
    public async Task<IActionResult> Picture()
    {
        if (!await _authorizationService.AuthorizeAsync(User, AccountPermissions.ViewOwnAccount) ||
            await CurrentAsync() is not { Page.Profile: { } profile } ||
            AccountProfileDisplayDriver.PhotoOf(profile) is not var (bytes, contentType))
        {
            return NotFound();
        }

        Response.Headers.CacheControl = "private, no-cache";
        Response.Headers.XContentTypeOptions = "nosniff";
        return File(bytes, contentType);
    }

    /// <summary>
    /// The signed-in user's own picture for the header and tiles: the site picture if set, else the domain picture,
    /// else 404. No id or name in the address; private to that user's browser, checked again on every use.
    /// </summary>
    [HttpGet("avatar")]
    public async Task<IActionResult> Avatar()
    {
        if (!await _authorizationService.AuthorizeAsync(User, AccountPermissions.ViewOwnAccount) || await CurrentAsync() is not { } current)
        {
            return NotFound();
        }

        Response.Headers.CacheControl = "private, no-cache";
        Response.Headers.XContentTypeOptions = "nosniff";
        if (await _sitePictures.ReadAsync(current.Page.User) is { } site)
        {
            return File(site, "image/jpeg");
        }

        if (current.Page.Profile is { } profile && AccountProfileDisplayDriver.PhotoOf(profile) is var (bytes, contentType))
        {
            return File(bytes, contentType);
        }

        return NotFound();
    }

    [HttpPost("password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Password()
    {
        if (!await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnDomainPassword) ||
            await CurrentAsync() is not { Page.IsLocal: false, Sid: { } sid } current)
        {
            return Forbid();
        }

        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        var currentPassword = form["CurrentPassword"].ToString();
        var newPassword = form["NewPassword"].ToString();
        var confirmPassword = form["ConfirmPassword"].ToString();
        var user = current.Page.User;
        var client = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        string[] attributes = ["unicodePwd"];

        if (AccountActions.ValidatePassword(currentPassword, newPassword, confirmPassword) is { } invalid)
        {
            await RecordAsync(user, client, "password", attributes, "invalid input");
            await _notifier.ErrorAsync(H[invalid]);
            return BackToPanel(AccountActions.PasswordPanelId);
        }

        if (!_limiter.TryAcquire(AccountActions.BindKey(user.UserId), AccountActions.PasswordAttempts, AccountActions.AttemptWindow))
        {
            await RecordAsync(user, client, "password", attributes, "rate limited");
            await _notifier.ErrorAsync(H[AccountActions.TooManyAttempts]);
            return BackToPanel(AccountActions.PasswordPanelId);
        }

        if (AccountName.Parse(user.UserName, _options.NetBiosName, _options.Domain) is not { } account)
        {
            await RecordAsync(user, client, "password", attributes, "refused");
            await _notifier.ErrorAsync(H[AccountActions.PasswordMessage(DirectoryWriteOutcome.Refused)]);
            return BackToPanel(AccountActions.PasswordPanelId);
        }

        var result = _writer.ChangePassword(account, sid, currentPassword, newPassword);
        await RecordAsync(user, client, "password", attributes, AccountActions.AuditOutcome(result.Outcome));

        if (result.Outcome == DirectoryWriteOutcome.Success)
        {
            if (result.Snapshot is { } snapshot)
            {
                await _snapshots.SaveAsync(user, snapshot);
            }

            // the Orchard session is untouched: the user stays signed in
            await _notifier.SuccessAsync(H[AccountActions.PasswordMessage(result.Outcome)]);
            return BackToAccount();
        }

        await _notifier.ErrorAsync(H[AccountActions.PasswordMessage(result.Outcome)]);
        return BackToPanel(AccountActions.PasswordPanelId);
    }

    /// <summary>Upload a new domain picture: checked, re-encoded to 96x96 JPEG here, written as thumbnailPhoto with the user's bind.</summary>
    [HttpPost("picture")]
    [ValidateAntiForgeryToken]
    [RequestSizeLimit(PictureProcessor.MaxUploadBytes + 64 * 1024)]
    [RequestFormLimits(MultipartBodyLengthLimit = PictureProcessor.MaxUploadBytes + 64 * 1024)]
    public async Task<IActionResult> UploadPicture()
    {
        if (!await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnDomainPicture) ||
            await CurrentAsync() is not { Page.IsLocal: false, Sid: { } sid } current)
        {
            return Forbid();
        }

        var user = current.Page.User;
        var client = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        string[] attributes = ["thumbnailPhoto"];

        IFormCollection form;
        try
        {
            form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        }
        catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException)
        {
            // over the size limit or not a well-formed form
            await RecordAsync(user, client, "picture", attributes, "invalid input");
            await _notifier.ErrorAsync(H[PictureProcessor.Message(PictureOutcome.TooLarge)]);
            return BackToPanel(AccountActions.PicturePanelId);
        }

        var currentPassword = form["CurrentPassword"].ToString();
        var file = form.Files["Picture"];

        string? invalid = AccountActions.ValidateCurrentPassword(currentPassword);
        if (invalid is null && (file is null || file.Length == 0))
        {
            invalid = PictureProcessor.Message(PictureOutcome.Missing);
        }
        else if (invalid is null && file!.Length > PictureProcessor.MaxUploadBytes)
        {
            invalid = PictureProcessor.Message(PictureOutcome.TooLarge);
        }

        byte[] upload = [];
        if (invalid is null)
        {
            using var buffer = new MemoryStream((int)file!.Length);
            await file.CopyToAsync(buffer, HttpContext.RequestAborted);
            upload = buffer.ToArray();

            // the cheap check first, so a wrong file type does not use up an attempt
            if (DirectorySnapshot.ImageType(upload) is null)
            {
                invalid = PictureProcessor.Message(PictureOutcome.WrongType);
            }
        }

        if (invalid is not null)
        {
            await RecordAsync(user, client, "picture", attributes, "invalid input");
            await _notifier.ErrorAsync(H[invalid]);
            return BackToPanel(AccountActions.PicturePanelId);
        }

        // the same budget as the password change: each try is a bind with a typed password
        if (!_limiter.TryAcquire(AccountActions.BindKey(user.UserId), AccountActions.PictureAttempts, AccountActions.AttemptWindow))
        {
            await RecordAsync(user, client, "picture", attributes, "rate limited");
            await _notifier.ErrorAsync(H[AccountActions.TooManyAttempts]);
            return BackToPanel(AccountActions.PicturePanelId);
        }

        var picture = PictureProcessor.Process(upload);
        if (picture.Outcome != PictureOutcome.Ok || picture.Jpeg is null)
        {
            await RecordAsync(user, client, "picture", attributes, "image " + picture.Outcome.ToString().ToLowerInvariant());
            await _notifier.ErrorAsync(H[PictureProcessor.Message(picture.Outcome)]);
            return BackToPanel(AccountActions.PicturePanelId);
        }

        if (AccountName.Parse(user.UserName, _options.NetBiosName, _options.Domain) is not { } account)
        {
            await RecordAsync(user, client, "picture", attributes, "refused");
            await _notifier.ErrorAsync(H[AccountActions.PictureMessage(DirectoryWriteOutcome.Refused)]);
            return BackToPanel(AccountActions.PicturePanelId);
        }

        var result = _writer.Replace(account, sid, currentPassword, new Dictionary<string, object?> { ["thumbnailPhoto"] = picture.Jpeg });
        await RecordAsync(user, client, "picture", attributes, AccountActions.AuditOutcome(result.Outcome));

        if (result.Outcome == DirectoryWriteOutcome.Success)
        {
            if (result.Snapshot is { } snapshot)
            {
                await _snapshots.SaveAsync(user, snapshot);
            }

            await _notifier.SuccessAsync(H[AccountActions.PictureMessage(result.Outcome)]);
            return BackToAccount();
        }

        await _notifier.ErrorAsync(H[AccountActions.PictureMessage(result.Outcome)]);
        return BackToPanel(AccountActions.PicturePanelId);
    }

    /// <summary>Phone, mobile and location (telephoneNumber, mobile, physicalDeliveryOfficeName) with the user's bind.</summary>
    [HttpPost("contact")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Contact([FromServices] LocationChoices locations)
    {
        if (!await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnContactDetails) ||
            await CurrentAsync() is not { Page.IsLocal: false, Sid: { } sid } current)
        {
            return Forbid();
        }

        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        var currentPassword = form["CurrentPassword"].ToString();
        var user = current.Page.User;
        var profile = current.Page.Profile;
        var client = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        var invalid = AccountActions.ValidateCurrentPassword(currentPassword);
        AccountActions.ContactValues? values = null;
        if (invalid is null)
        {
            // no Location choices configured: the field is not offered and the current value is kept as it is
            var offices = await locations.NamesAsync();
            var office = offices.Count > 0 ? form["Office"].ToString() : profile?.Office;
            (invalid, values) = AccountActions.ValidateContact(
                form["TelephoneNumber"].ToString(), form["Mobile"].ToString(), office,
                offices, profile?.Office);
        }

        if (invalid is not null || values is null)
        {
            await RecordAsync(user, client, "contact", ["telephoneNumber", "mobile", "physicalDeliveryOfficeName"], "invalid input");
            await _notifier.ErrorAsync(H[invalid ?? AccountActions.ContactMessage(DirectoryWriteOutcome.Refused)]);
            return BackToPanel(AccountActions.ContactPanelId);
        }

        // write only what differs from the snapshot; nothing to write means no bind and no attempt used
        var changes = AccountActions.ContactChanges(values, profile?.TelephoneNumber, profile?.Mobile, profile?.Office);
        if (changes.Count == 0)
        {
            await _notifier.InformationAsync(H[AccountActions.NothingChanged]);
            return BackToAccount();
        }

        var attributes = changes.Keys.ToArray();
        if (!_limiter.TryAcquire(AccountActions.BindKey(user.UserId), AccountActions.ContactAttempts, AccountActions.AttemptWindow))
        {
            await RecordAsync(user, client, "contact", attributes, "rate limited");
            await _notifier.ErrorAsync(H[AccountActions.TooManyAttempts]);
            return BackToPanel(AccountActions.ContactPanelId);
        }

        if (AccountName.Parse(user.UserName, _options.NetBiosName, _options.Domain) is not { } account)
        {
            await RecordAsync(user, client, "contact", attributes, "refused");
            await _notifier.ErrorAsync(H[AccountActions.ContactMessage(DirectoryWriteOutcome.Refused)]);
            return BackToPanel(AccountActions.ContactPanelId);
        }

        var result = _writer.Replace(account, sid, currentPassword, changes);
        await RecordAsync(user, client, "contact", attributes, AccountActions.AuditOutcome(result.Outcome));

        if (result.Outcome == DirectoryWriteOutcome.Success)
        {
            if (result.Snapshot is { } snapshot)
            {
                await _snapshots.SaveAsync(user, snapshot);
            }

            await _notifier.SuccessAsync(H[AccountActions.ContactMessage(result.Outcome)]);
            return BackToAccount();
        }

        await _notifier.ErrorAsync(H[AccountActions.ContactMessage(result.Outcome)]);
        return BackToPanel(AccountActions.ContactPanelId);
    }

    /// <summary>Upload the picture shown on this site: same checks as the domain picture, 256x256 JPEG, into the Media library.</summary>
    [HttpPost("site-picture")]
    [ValidateAntiForgeryToken]
    [RequestSizeLimit(PictureProcessor.MaxUploadBytes + 64 * 1024)]
    [RequestFormLimits(MultipartBodyLengthLimit = PictureProcessor.MaxUploadBytes + 64 * 1024)]
    public async Task<IActionResult> UploadSitePicture()
    {
        if (!await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnSitePicture) ||
            await CurrentAsync() is not { } current)
        {
            return Forbid();
        }

        var user = current.Page.User;
        var client = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        string[] attributes = ["SiteProfile.Picture"];

        IFormCollection form;
        try
        {
            form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        }
        catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException)
        {
            await RecordAsync(user, client, "site-picture", attributes, "invalid input");
            await _notifier.ErrorAsync(H[PictureProcessor.Message(PictureOutcome.TooLarge)]);
            return BackToPanel(AccountActions.SitePicturePanelId);
        }

        var file = form.Files["Picture"];
        if (file is null || file.Length == 0 || file.Length > PictureProcessor.MaxUploadBytes)
        {
            await RecordAsync(user, client, "site-picture", attributes, "invalid input");
            await _notifier.ErrorAsync(H[PictureProcessor.Message(file is null || file.Length == 0 ? PictureOutcome.Missing : PictureOutcome.TooLarge)]);
            return BackToPanel(AccountActions.SitePicturePanelId);
        }

        // its own budget: no directory bind here, but decoding costs work
        if (!_limiter.TryAcquire("site-picture:" + user.UserId, AccountActions.SitePictureAttempts, AccountActions.AttemptWindow))
        {
            await RecordAsync(user, client, "site-picture", attributes, "rate limited");
            await _notifier.ErrorAsync(H[AccountActions.TooManyAttempts]);
            return BackToPanel(AccountActions.SitePicturePanelId);
        }

        byte[] upload;
        using (var buffer = new MemoryStream((int)file.Length))
        {
            await file.CopyToAsync(buffer, HttpContext.RequestAborted);
            upload = buffer.ToArray();
        }

        var picture = PictureProcessor.Process(upload, SitePictureStore.Size, SitePictureStore.MaxOutputBytes);
        if (picture.Outcome != PictureOutcome.Ok || picture.Jpeg is null)
        {
            await RecordAsync(user, client, "site-picture", attributes, "image " + picture.Outcome.ToString().ToLowerInvariant());
            await _notifier.ErrorAsync(H[PictureProcessor.Message(picture.Outcome)]);
            return BackToPanel(AccountActions.SitePicturePanelId);
        }

        await _sitePictures.SaveAsync(user, picture.Jpeg);
        await RecordAsync(user, client, "site-picture", attributes, "success");
        await _notifier.SuccessAsync(H["Your picture on this site has been changed."]);
        return BackToAccount();
    }

    [HttpPost("site-picture/remove")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveSitePicture()
    {
        if (!await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnSitePicture) ||
            await CurrentAsync() is not { } current)
        {
            return Forbid();
        }

        var user = current.Page.User;
        var client = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var removed = await _sitePictures.RemoveAsync(user);
        await RecordAsync(user, client, "site-picture-remove", ["SiteProfile.Picture"], removed ? "success" : "nothing to remove");
        await _notifier.SuccessAsync(H[removed ? "Your picture on this site has been removed." : "There was no picture to remove."]);
        return BackToAccount();
    }

    // every account action: Tor's audit log, and Orchard's Audit Trail when it is on (names and outcomes, never values)
    private async Task RecordAsync(User user, string client, string action, IReadOnlyCollection<string> attributes, string outcome)
    {
        _audit.Action(user.UserName, client, action, attributes, outcome);
        await _recorder.RecordAsync(user, action, attributes, outcome);
    }

    private LocalRedirectResult BackToAccount() => LocalRedirect("~/account");

    // after a failure the panel stays open: a theme can show it when the address ends in its id
    private LocalRedirectResult BackToPanel(string panelId) => LocalRedirect("~/account#" + panelId);

    private async Task<(AccountPage Page, string? Sid)?> CurrentAsync()
    {
        if (await _userManager.GetUserAsync(User) is not User user)
        {
            return null;
        }

        var logins = await _userManager.GetLoginsAsync(user);
        var sid = logins.FirstOrDefault(l => l.LoginProvider == DirectoryUserSync.LoginProvider)?.ProviderKey;
        var isLocal = sid is null;

        var page = new AccountPage
        {
            User = user,
            IsLocal = isLocal,
            Profile = isLocal ? null : SnapshotStore.Read(user),
            CanChangePassword = !isLocal && await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnDomainPassword),
            CanChangePicture = !isLocal && await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnDomainPicture),
            CanChangeContact = !isLocal && await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnContactDetails),
            CanChangeSitePicture = await _authorizationService.AuthorizeAsync(User, AccountPermissions.ChangeOwnSitePicture),
            SitePictureUrl = _sitePictures.UrlOf(user),
        };

        return (page, sid);
    }
}
