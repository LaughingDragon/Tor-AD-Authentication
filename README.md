# Tor: Active Directory sign-in for Orchard Core

**Status: preview (0.1.0-preview).** This release has been verified on one production site; an
earlier version of Tor has run on several sites. A line-by-line security review of this release is
in progress. Report problems through GitHub's private vulnerability reporting (Security tab), not as
a public issue.

Tor is an [Orchard Core](https://orchardcore.net/) module that lets Active Directory domain accounts
sign in on Orchard's own login page. A companion feature, **Tor Account**, gives each signed-in user
an account page at `/account` that shows their own directory details and lets them change their
domain password, domain picture and contact details.

Tor is MIT licensed (see [`LICENSE`](LICENSE)).

## How it works

- **It binds as the signing-in user.** Tor takes the name and password typed on Orchard's login form
  and binds to the domain controllers with them (Negotiate over LDAPS, port 636). There is no service
  account, and Tor stores no directory password. Everything Tor reads about the user is read with the
  user's own bind.
- **Access is gated by group membership.** After the bind, Tor reads the user's `tokenGroups`
  (nested groups included) and compares them with the groups named in the `GroupRoles` setting. A
  user in none of those groups is refused.
- **Groups map only to the roles you configure, and only those roles are touched.** Each group in
  `GroupRoles` names one Orchard role. The map is **empty by default**: until you configure it, no
  directory account can sign in. At every sign-in Tor adds the mapped roles the user should have and
  removes mapped roles the user no longer qualifies for. It never adds or removes a role that is not
  in the mapping.
  - **Administrator is refused unless you allow it.** An entry that maps a group to `Administrator`
    (any letter case), or to the role Orchard reports as its admin role, is ignored with a warning in
    the log unless `AllowAdministratorMapping` is `true`. When it is `true`, a warning is logged at
    start-up. While the flag is off, the user's other mapped roles still apply.
  - **Roles that do not exist are not granted.** A mapped role that does not exist in Orchard is
    ignored with a warning; Tor does not create roles. A user whose mapped roles all cannot be
    granted is refused.
  - The effective mapping (group and role names only) is written to the `Tor.Audit` log at start-up.
- **Sign-in throttling.** Failed sign-ins are counted per user name and per client address in a
  fixed window. The defaults are **5 failures per user name** and **20 failures per client address**
  in **15 minutes**, and all three are configurable (`MaxFailuresPerUser`, `MaxFailuresPerClient`,
  `FailureWindowMinutes`). While a name or address is blocked, Tor does not contact the domain at
  all, so attempts through the site stop adding to the domain's own lockout count. A domain that
  cannot be reached is not counted against the user. A successful sign-in clears the user name's
  count, not the client address's.
- **A local break-glass administrator.** Orchard user names listed in `LocalAccounts` keep
  Orchard's normal password sign-in, so the site can be administered when the domain cannot be
  reached. They are throttled and logged like domain sign-ins.
- **Audit logging.**
  - Every sign-in attempt, successful or not, writes one line to the logger `Tor.Audit`: the
    outcome, the reason for a failure, the user name as typed (control characters removed, at most
    128 characters), the client address and whether it was a local or a directory sign-in. Never a
    password.
  - Directory sign-ins raise the same Orchard login events as Orchard's own login (see
    [Orchard's login checks](#orchards-login-checks)). With Orchard's **Users Audit Trail** feature
    enabled, a successful sign-in is recorded in Orchard's **Audit Trail** as "Logged in", a failed
    one as "Login failed" (user name as typed, never a password) and a locked-out one as "Login
    account locked". Orchard ships "Login failed" switched off; tick it under **Settings > Audit
    Trail > User** to record failures. The client address is in the Audit Trail only when its
    "Allow client IP address" setting is on; it is always in `Tor.Audit`.
  - Every account action on `/account` is written to `Tor.Audit` and, when Orchard's **Audit Trail**
    feature is enabled, to the Audit Trail under the category **Account** (the action, the names of
    the attributes involved and the outcome; never a value or a password).

More detail on a sign-in:

1. Orchard's anti-forgery check runs first. Tor's action filter then runs on the POST of Orchard's
   `AccountController.LoginPOST` (`OrchardCore.Users`). Tor adds no login page of its own.
2. A name listed in `LocalAccounts`, typed as a plain name (no `\` or `@`), goes on to Orchard's
   normal password sign-in. Any other name is a domain sign-in.
3. Orchard's login-form event `LoggingInAsync` is raised for every subscriber (this is where, for
   example, Orchard's reCAPTCHA checks the form). If any subscriber reports an error or fails, the
   sign-in is refused **before any directory call**.
4. Tor's throttle is checked. The name may be `name`, `DOMAIN\name` (NetBIOS or DNS domain name of
   the configured domain) or a user principal name. Anything else fails.
5. Tor binds as the user and reads, with that bind: the bind's own identity (WhoAmI), the user's
   object (SID, `sAMAccountName`, UPN, display name, mail, account control flags, expiry) and its
   `tokenGroups`, and the SIDs of the mapped groups.
6. The account is refused if it is disabled, locked out or expired, if its password has expired,
   or if it is in none of the mapped groups.
7. The Orchard user is matched by the account's SID, stored as an external login (provider `Tor`).
   If none matches, Tor creates an Orchard user with user name = `sAMAccountName`, email = `mail`
   (else the UPN) and a random 48-character local password that is never shown. If an Orchard user
   without that link already has the same user name, Tor refuses: it never takes over a local
   account. Mapped roles are added and removed as described above.
8. Orchard's checks on the user run, as after a good password in Orchard's own login: the user
   must be enabled, not locked out in Orchard, and allowed to sign in by Orchard's sign-in rules
   (`SignInManager.CanSignInAsync`), and no `ValidatingLoginAsync` subscriber (for example email
   confirmation or user moderation) may object.
9. A user with two-factor authentication turned on in Orchard, or required by Orchard's two-factor
   settings, is refused (see [Limitations](#limitations)). No cookie is issued.
10. Tor signs the user in with a non-persistent cookie, raises `LoggedInAsync` once, raises Orchard's
    `UserLoggedInEvent` workflow event when Workflows is enabled, and redirects to the return URL if
    it is local, otherwise to the site root.

Every failure, whatever its cause, gives the same answer: Orchard's "Invalid login attempt." and a
redirect to the login page. Orchard's `LoggingInFailedAsync` event is raised exactly once per
failure. The cause goes only to Tor's `Tor.Audit` log. An unexpected error during a directory
sign-in also fails closed with the same answer. LDAP filter values are escaped (RFC 4515).

## Orchard's login checks

How a directory sign-in compares with Orchard Core 3.0.1's own password login
(`AccountController.LoginPOST`):

| Orchard's login | Directory sign-in through Tor |
|---|---|
| `LoggingInAsync` for every subscriber; errors stop the login | The same, before any directory call. Stricter: a subscriber that throws also stops the sign-in (Orchard logs it and carries on). |
| Password check (`CheckPasswordSignInAsync`, counts towards Orchard's lockout) | Tor's throttle, then the bind as the user and the group gate. A failed bind does not count towards Orchard's lockout counter; the domain's own lockout and Tor's throttle apply instead. |
| `ValidatingLoginAsync` for every subscriber (disabled user, email confirmation, moderation) | The same subscribers are asked, after Tor's own checks that the user is enabled, not locked out in Orchard and allowed by `CanSignInAsync`. Any objection refuses the sign-in with the generic answer; Orchard's own redirect (for example to the email confirmation page) is not used. |
| Locked out: "The account is locked out", `IsLockedOutAsync` | Refused with the generic answer; `IsLockedOutAsync` and `LoggingInFailedAsync` are raised. |
| Two-factor: redirect to Orchard's two-factor step | Refused with the generic answer (not supported for directory sign-in). |
| Success: cookie (optionally persistent, "Remember me"), `LoggedInAsync`, `UserLoggedInEvent` workflow event | Cookie (never persistent; "Remember me" is ignored), `LoggedInAsync` once, `UserLoggedInEvent` once. |
| Failure: "Invalid login attempt.", `LoggingInFailedAsync` once | The same message and event, for every cause. |

Local break-glass accounts (`LocalAccounts`) go through Orchard's own login unchanged and get all of
Orchard's checks. When Tor's throttle blocks one, Orchard's login does not run, and Tor raises
`LoggingInFailedAsync` itself.

While the Tor feature is enabled it also sets Orchard's sign-in cookie, for every sign-in, to
`HttpOnly`, `Secure` (HTTPS only), `SameSite=Lax`, with an 8-hour sliding expiry. While it is
disabled, Tor does nothing and Orchard's sign-in behaves as it does without Tor.

## Requirements

What this was built and tested with:

- Orchard Core **3.0.1**
- .NET **10** (SDK 10.0)
- An Active Directory domain whose domain controllers accept LDAPS on port 636, with certificates
  that name each server as it is listed in `Servers`, and that the web server trusts.
- Orchard features: `OrchardCore.Users` and `OrchardCore.Roles` (Tor); additionally
  `OrchardCore.Users.CustomUserSettings` and `OrchardCore.Media` (Tor Account). `OrchardCore.AuditTrail`,
  Orchard's Users Audit Trail and Workflows are optional.
- Packages: the module references Orchard's `OrchardCore.Media` package, which brings
  SixLabors.ImageSharp (used for the account page's picture uploads); see `NOTICE.md`.

Other versions of Orchard Core or .NET have not been tested.

## Installation

Tor is distributed as source. It is not published as a NuGet package.

1. Copy `src/Tor` into your Orchard Core web solution (or add this repository as a submodule) and
   add a project reference to `Tor.csproj` from your Orchard web project.
2. This repository uses central package management. If your solution does not, add the package
   versions from [`Directory.Packages.props`](Directory.Packages.props) to `Tor.csproj`; if it does,
   add those `PackageVersion` entries to yours.
3. Add the configuration below to the server's settings (not to the repository).
4. Build and deploy the site, then in the Orchard admin go to **Configuration > Features** and
   enable **Tor**, then (optionally) **Tor Account**.

To build and test this repository on its own:

```
dotnet restore Tor.slnx
dotnet build Tor.slnx
dotnet test Tor.slnx
```

## Upgrading from earlier versions

- **There is no default role mapping any more.** Earlier versions mapped `Intranet-Users` to
  `Intranet Users`, `Intranet-Admins` to `Administrator` and `Intranet-Guests` to `Guests` by
  default. This release has no default mapping: before upgrading, add an explicit `GroupRoles` entry
  for every group that should be able to sign in, or no directory account can sign in.
- **Administrator needs the flag.** Set `AllowAdministratorMapping` to `true` only if a group should
  map to `Administrator`; without it, that entry is ignored.
- **Keep a local break-glass account** in `LocalAccounts` (and its password) available before
  upgrading, so you can still sign in if the mapping is wrong.
- **Two-factor directory accounts are refused.** A directory user with Orchard two-factor
  authentication turned on, or required for them, can no longer sign in through the directory.
- **Failed sign-ins in the Audit Trail.** Failed directory sign-ins reach Orchard's Audit Trail only
  if Orchard's Users Audit Trail feature is enabled and **Settings > Audit Trail > User > Login
  failed** is ticked (Orchard ships it unticked). They are always in the `Tor.Audit` log.

## Configuration

Tor reads the section `OrchardCore:Tor` of the site's configuration (for example
`appsettings.Production.json` on the server). All values below are examples.

```json
{
  "OrchardCore": {
    "Tor": {
      "Domain": "corp.example.com",
      "NetBiosName": "CORP",
      "Servers": [ "dc01.corp.example.com", "dc02.corp.example.com" ],
      "UseLdaps": true,
      "TimeoutSeconds": 10,
      "GroupRoles": {
        "Intranet-Users": "Intranet Users",
        "Intranet-Guests": "Guests",
        "Intranet-Admins": "Administrator"
      },
      "AllowAdministratorMapping": false,
      "LocalAccounts": [ "breakglass-admin" ],
      "MaxFailuresPerUser": 5,
      "MaxFailuresPerClient": 20,
      "FailureWindowMinutes": 15,
      "OfficeChoices": [ "Head Office", "North Wing" ]
    }
  }
}
```

| Setting | Default | Meaning |
|---|---|---|
| `Domain` | (empty) | DNS name of the domain. |
| `NetBiosName` | (empty) | NetBIOS name of the domain. Required. |
| `Servers` | (empty) | Domain controller host names, as named on their LDAPS certificates. Required. |
| `UseLdaps` | `true` | LDAPS on port 636. When `false`, sign-in uses LDAP on port 389 with Negotiate signing and sealing, and the password change on `/account` is refused. |
| `TimeoutSeconds` | `10` | LDAP timeout. |
| `GroupRoles` | (empty) | Group (`sAMAccountName`) → Orchard role. The sign-in gate and the only roles Tor manages. With no entries, no directory account can sign in. Entries for roles that do not exist are ignored with a warning. |
| `AllowAdministratorMapping` | `false` | Whether an entry may map a group to `Administrator` (or to Orchard's admin role). While `false`, such entries are ignored with a warning. When `true`, a warning is logged at start-up. |
| `LocalAccounts` | (empty) | Orchard user names that keep Orchard's password sign-in (break-glass). |
| `MaxFailuresPerUser` | `5` | Failed sign-ins allowed per user name in the window. |
| `MaxFailuresPerClient` | `20` | Failed sign-ins allowed per client address in the window. |
| `FailureWindowMinutes` | `15` | Length of the throttling window. |
| `OfficeChoices` | (empty) | Tor Account: fixed choices for the Location field. |
| `OfficeContentType` | (empty) | Tor Account, optional: a content type whose published titles are added to the Location choices. |
| `OfficePathPrefix` | (empty) | Tor Account, optional: with `OfficeContentType`, only items whose address starts with this path. |

In this example the `Intranet-Admins` entry is ignored, because `AllowAdministratorMapping` is
`false`: members of `Intranet-Admins` who are in no other mapped group cannot sign in, and members
who are also in `Intranet-Users` sign in with `Intranet Users` only. Set the flag to `true` only if
a directory group really should make its members Orchard administrators.

Turning `AllowAdministratorMapping` off later does not take `Administrator` away from users who
already have it: while the flag is off, Tor no longer manages that role. Remove it by hand under
**Security > Users** if needed.

If `Servers` or `NetBiosName` is missing, every domain sign-in fails and an error is logged. Tor
does not create roles; create the mapped roles in Orchard first.

Tor's audit lines use the logger name `Tor.Audit`; route that logger to a file or other target in
your logging configuration if you want them kept apart.

## The break-glass account

- Create a normal Orchard user (for example during Orchard setup) and list its user name in
  `LocalAccounts`.
- Typed as a plain name on the login page, it signs in with Orchard's own password check, not
  through the domain. Typed as `DOMAIN\name` or `name@domain`, it is treated as a domain sign-in.
- It has no directory link, so on `/account` it has no directory details and no domain actions; it
  can only set its picture on the site.
- It is throttled under its own key and every attempt is written to `Tor.Audit`.
- Give it a long, unique password, and keep the list short.

## The account page (Tor Account)

`/account` always describes the signed-in user. No route or form takes a user id; every action works
on the signed-in user, and every directory action binds as that user and checks that the bound
account's SID is the SID linked to the Orchard user. Forms post and redirect back to `/account`, so
no typed value is ever shown again.

**Directory details.** At each directory sign-in, Tor saves a snapshot of the user's own directory
object on the Orchard user (Custom User Settings type `DirectoryProfile`): display name, mail, UPN,
title, department, description, telephone number, mobile, office, when created, password last set
and expiry, last logon, account expiry, enabled, home directory, mapped groups, computers whose
`managedBy` is the user, and `thumbnailPhoto` (JPEG or PNG up to 100 KB). Values are length-capped.
The page shows the snapshot "as of your last sign-in"; it is not read live.

**Actions**, each asking for the current password and binding as the user:

| Action | Writes | Notes |
|---|---|---|
| Change domain password | `unicodePwd` | LDAPS only. The domain's password policy applies. The Orchard session stays signed in. |
| Change domain picture | `thumbnailPhoto` | JPEG or PNG up to 2 MB, at most 12,000 pixels a side and 40 million pixels; re-encoded to a 96×96 JPEG without metadata. |
| Change contact details | `telephoneNumber`, `mobile`, `physicalDeliveryOfficeName` | Only values that differ are written. Phones: digits, spaces and `+ - ( ) .`, at most 64 characters. Location: one of the configured choices; with no choices configured there is no Location field and it is never written. |
| Picture on this site | Orchard Media library | 256×256 JPEG in `site-profile/{user id}/` with a random file name; no domain bind. Available to local accounts too. Can be removed. |

Only the attributes in the table can be written; anything else is refused before the directory is
contacted.

**Limits.** The three domain actions share one budget per user of 3 attempts in 15 minutes, so that
together with sign-in failures they stay below a typical domain lockout threshold. The site picture
has its own budget of 10 uploads in 15 minutes. These limits are fixed in code.

**Permissions.** `ManageOwnAccount` implies all of the others: `ViewOwnAccount`,
`ChangeOwnDomainPassword`, `ChangeOwnDomainPicture`, `ChangeOwnContactDetails`,
`ChangeOwnSitePicture`. When the feature is first enabled, Orchard grants them by default to roles
of these names if they exist: `Administrator` (all), `Intranet Users` (`ManageOwnAccount`) and
`Guests` (`ViewOwnAccount`, `ChangeOwnDomainPassword`, `ChangeOwnSitePicture`). Adjust them under
**Security > Roles**.

**Other addresses.** `/account/picture` returns the user's own domain picture and `/account/avatar`
the site picture or, failing that, the domain picture; both are sent with `Cache-Control: private,
no-cache`.

**Theming.** The page is built from the shapes `AccountPage`, `AccountProfile`, `AccountPassword`,
`AccountPicture`, `AccountContact` and `AccountSitePicture`. The module has plain Razor templates for
each; a theme can override them (for example with Liquid templates of the same names).

## Tests

`tests/Tor.Tests` holds unit tests for name parsing, group-to-role mapping (including the
`AllowAdministratorMapping` guard and how configuration binds), SIDs, LDAP escaping, bind error
classification, expiry, throttling, audit text, the account actions, picture processing and the
Location choices. `LoginFilterTests.cs` checks the directory sign-in against Orchard's login
sequence with stand-ins for the directory, the Orchard user and Orchard's login events: the order of
the events, no directory call after a login-form error, one failure event per failure, one success
event per success, no cookie on any failure, the same answer for every failure, and no password in
any log line or event. No unit test contacts a domain controller.

`DomainIntegrationTests.cs` runs against a real domain from a domain-joined Windows machine. It
reads two test accounts' credentials from Windows Credential Manager (targets `Tor-Test-Member` and
`Tor-Test-Outsider`, see the file header) and is skipped when they are not stored. It never prints
a password.

## Limitations

- **Two-factor accounts are refused, not supported.** A directory sign-in is the user name and
  password only. A directory user who has two-factor authentication turned on in Orchard, or for whom
  Orchard requires it (site-wide or by role), cannot sign in through the directory: the sign-in is
  refused with the generic answer, and the cause is logged. Do not turn on Orchard's two-factor
  requirement for roles that directory users hold. Orchard's two-factor sign-in still works for the
  local break-glass accounts.
- **The answer never says why a sign-in failed**, including for two-factor accounts and Orchard
  objections such as an unconfirmed email. Users must ask an administrator, who finds the cause in
  the `Tor.Audit` log.
- **"Remember me" is ignored** for directory sign-ins: the cookie is never persistent.
- **No single sign-on.** Users type their domain password on the site's login page; there is no
  Kerberos or Windows integrated sign-in.
- **Preview release.** A line-by-line security review of this release is in progress and is not yet
  complete.
- **This release is verified on one production site only**, on Windows Server with IIS, Orchard
  Core 3.0.1 and .NET 10. An earlier version of Tor has run on several sites.
- **LDAPS required.** LDAPS is the default and the configuration that was used in production; the
  password change works only over LDAPS. The signed-and-sealed LDAP fallback for sign-in exists but
  is not recommended.
- **Throttling is in memory, per process.** An application restart clears the counts, and several
  web servers each count separately. The domain's own lockout policy still applies.
- **Role mapping is only as narrow as its configuration.** Only `Administrator` (and Orchard's admin
  role) is guarded by `AllowAdministratorMapping`. Any other role you map is granted as configured,
  including a custom role that carries administrator-level permissions.
- **Pictures:** EXIF orientation is not applied (metadata is skipped on purpose), so a sideways phone
  photo stays sideways. Picture processing uses SixLabors.ImageSharp 3.1.12 (through Orchard's
  Media package), which has published advisories that NuGet audit reports at restore; see `NOTICE.md`.
- **The snapshot is as of the last sign-in or account action**, not live.

## Licence

MIT. Copyright (c) 2026 Liam P. Ward. See [`LICENSE`](LICENSE). Third-party packages are listed with
their licences in [`NOTICE.md`](NOTICE.md). Vulnerability reporting: [`SECURITY.md`](SECURITY.md).
