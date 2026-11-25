# Configuration reference (Tor 1.0)

This is what Tor 1.0 promises to keep. Within 1.x, the setting keys, their defaults and their ranges,
the feature ids, the permission names, the claim type, the user login provider and the log event
texts below only change in a new major version. A setting or behaviour that is to be removed is
first marked deprecated in the CHANGELOG and keeps working for at least one minor release. New
settings may be added in a minor release; their default keeps the earlier behaviour.

The tests in `tests/Tor.Tests/UpgradeTests.cs` check that the settings of 0.1.0-preview.1 still load
unchanged, that the defaults are the ones listed here, and that this page lists every setting.

## Settings

Tor reads the section `OrchardCore:Tor` of the site's configuration (for example
`appsettings.Production.json`, environment variables such as `OrchardCore__Tor__Domain`, or a
tenant's own settings). A sample is in the README, under Configuration.

| Key | Type | Default | Range or rule | Meaning |
|---|---|---|---|---|
| `Domain` | text | (empty) | required | DNS name of the domain, for example `corp.example.com`. |
| `NetBiosName` | text | (empty) | required | NetBIOS name of the domain, for example `CORP`. |
| `Servers` | list of text | (empty) | at least one, no empty entry | Domain controller host names, as named on their LDAPS certificates; handed to the LDAP connection as one list. |
| `UseLdaps` | true/false | `true` | | LDAPS on port 636. When `false`: LDAP on port 389 with Negotiate signing and sealing; the password change on `/account` is refused and a warning is logged at start-up. |
| `TimeoutSeconds` | whole number | `10` | 1 to 60 | LDAP time-out per server. |
| `GroupRoles` | map: group → role | (empty) | | Directory group (`sAMAccountName`, not case-sensitive) → Orchard role. The sign-in gate and the only roles Tor adds or removes. With no entries nobody can sign in through the directory. Entries for roles that do not exist, and entries with an empty group or role, are ignored with a warning. |
| `AllowAdministratorMapping` | true/false | `false` | | Whether an entry may map to `Administrator` or to Orchard's admin role. While `false` such entries are ignored with a warning; when `true` a warning is logged at start-up. |
| `LocalAccounts` | list of text | (empty) | | Orchard user names that keep Orchard's own password sign-in (break-glass). Only their number is ever logged. |
| `MaxFailuresPerUser` | whole number | `5` | at least 1 | Failed sign-ins allowed per user name in the window. |
| `MaxFailuresPerClient` | whole number | `20` | at least 1 | Failed sign-ins allowed per client address in the window. |
| `FailureWindowMinutes` | whole number | `15` | at least 1 | Length of the throttling window, in minutes. |
| `MaxSessionHours` | whole number | `12` | 1 to 720 | Absolute session lifetime: every sign-in, directory or local, ends this many hours after it was made. Orchard's sliding expiry still applies within it. |
| `OfficeChoices` | list of text | (empty) | | Tor Account: fixed choices for the Location field (`physicalDeliveryOfficeName`). With none here and no `OfficeContentType`, the Location field is not offered. |
| `OfficeContentType` | text | (empty) | optional | Tor Account: a content type whose published titles are added to the Location choices. |
| `OfficePathPrefix` | text | (empty) | optional | Tor Account, with `OfficeContentType`: only items whose address starts with this path. |

**When a setting is wrong** (a required one empty, or a number out of range), Tor logs one error for
each problem at tenant start and refuses every directory sign-in until it is fixed. Those refusals
do not count against the user. The break-glass accounts still work and the throttle never switches
off. Tor never stops the site over a setting.

**Fixed limits** (not settings; part of the 1.x promise too): passwords up to 256 characters;
domain picture uploads up to 2 MB and 16 million pixels (12,000 on a side), JPEG or PNG; the domain
picture is stored as a 96 × 96 JPEG of at most 100 KB, the site picture as 256 × 256 of at most
200 KB; telephone numbers up to 64 characters, Location up to 128; account actions per user and
15 minutes: 3 password, 3 picture, 3 contact and 10 site-picture attempts.

## Features

| Id | Name | Depends on | What it adds |
|---|---|---|---|
| `Tor` | Tor | `OrchardCore.Users`, `OrchardCore.Roles` | Directory sign-in on Orchard's login page, the throttle, role mapping, the session lifetime, the `Tor.Audit` log. |
| `Tor.Account` | Tor Account | `Tor`, `OrchardCore.Users.CustomUserSettings`, `OrchardCore.Media` | The account page at `/account`, the directory snapshot and the account actions. |

Both are in the **Security** category. The module itself is not a feature.

## What Tor sets on Orchard users

- **User name:** the directory account's `sAMAccountName`. A local Orchard user with the same name
  and no directory link is never taken over (the sign-in is refused).
- **External login:** login provider `Tor`, key = the account's SID, display name "Active
  Directory". This link is how Tor recognises the user later, even after a rename.
- **Email:** the directory `mail` attribute, or the user principal name when there is none; marked
  confirmed. Not applied when another user already has it (a warning is logged).
- **Password:** a random local password nobody sees; directory users always sign in through Tor.
- **Claim:** `tor:display_name` = the directory display name, added or replaced at each sign-in.
- **Roles:** only the roles named in `GroupRoles` are added or removed, at every sign-in. Roles Tor
  does not manage are left alone. Tor never creates roles.
- **Sign-in cookie property:** `Tor.SessionStarted` (the time of sign-in, used for the absolute
  lifetime).
- **Tor Account content types** (Custom User Settings): `DirectoryProfile` (part
  `DirectoryProfilePart`, the snapshot taken at sign-in) and `SiteProfile` (Media field `Picture`;
  files in the Media folder `site-profile/`).

## Permissions (Tor Account)

| Permission | Implied by | Default roles (stereotypes) |
|---|---|---|
| `ManageOwnAccount`: Manage own account (all account actions) | | Administrator, Intranet Users |
| `ViewOwnAccount`: View own account page | `ManageOwnAccount` | Administrator, Guests |
| `ChangeOwnDomainPassword`: Change own domain password | `ManageOwnAccount` | Administrator, Guests |
| `ChangeOwnDomainPicture`: Change own domain picture | `ManageOwnAccount` | Administrator |
| `ChangeOwnContactDetails`: Change own domain contact details | `ManageOwnAccount` | Administrator |
| `ChangeOwnSitePicture`: Change own site profile picture | `ManageOwnAccount` | Administrator, Guests |

The default roles only apply to roles of those names when Orchard assigns default permissions; Tor
does not create the roles.

## Addresses (Tor Account)

`GET /account`, `GET /account/picture` (the domain picture), `GET /account/avatar` (the site
picture), `POST /account/password`, `POST /account/picture`, `POST /account/contact`,
`POST /account/site-picture`, `POST /account/site-picture/remove`. Every response is sent with
`Cache-Control: private, no-store`; the pictures also with `X-Content-Type-Options: nosniff`.

## Log events

**Logger `Tor.Audit`** (one line per sign-in attempt and per account action; typed names are cut to
128 characters and stripped of control and format characters; passwords are never logged):

| Level | Text |
|---|---|
| Information | `Sign-in succeeded: user={UserName} client={Client} via={Path}` (`via` is `local`, `directory LDAPS 636, Negotiate` or `directory LDAP 389, Negotiate signed and sealed`) |
| Warning | `Sign-in failed: user={UserName} client={Client} via={Path} reason={Reason}` |
| Information / Warning | `Account action: user={UserName} client={Client} action={Action} attributes={Attributes} outcome={Outcome}` (Warning when the action failed) |
| Information | `Local accounts configured: {Count}` (at tenant start) |
| Warning | `LocalAccounts is empty: no local (break-glass) account can sign in, only directory accounts.` |
| Warning | `Role mapping is empty: no directory account can sign in until GroupRoles is configured.` |

The `reason` values of a failed sign-in: `bad credentials`, `account disabled`, `account locked`,
`account expired`, `password expired`, `account not readable`, `directory unavailable`,
`rate limited`, `not a valid domain username`, `password longer than 256 characters`,
`not in a managed group`, `no mapped role can be granted`, `Orchard user disabled`,
`Orchard user locked out`, `Orchard does not allow this user to sign in (confirmation required)`,
`username belongs to an unlinked Orchard user`, `Orchard user could not be created`,
`SID could not be stored`, `two-factor account: not supported for directory sign-in`,
`Tor is not configured correctly`, `local login refused`, `refused`,
`login form check failed ({event handler})`, `Orchard login check refused ({event handler})` and
`error {exception type}`. Of the directory failures, only `directory unavailable`, `rate limited` and `Tor is not configured
correctly` do not count towards the throttle.

**Tor's other loggers** (class names under `Tor.`): start-up and configuration messages, all
beginning with `Tor` or `Tor configuration:`, for example `Tor configuration: {Problem}; every
directory sign-in is refused until it is fixed.`, the `UseLdaps` and `AllowAdministratorMapping`
warnings, ignored `GroupRoles` entries, and failures of other modules' login handlers. These texts
may gain detail in a minor release; the `Tor.Audit` texts above do not change within 1.x.

**Orchard's Audit Trail** (when Orchard's Audit Trail is enabled):

- Category **Account**, events `DomainPassword`, `DomainPicture`, `ContactDetails`, `SitePicture`
  and `SitePictureRemoved` (on by default).
- Failed directory sign-ins appear as Orchard's own **User > Login failed** event when the Users
  Audit Trail feature is enabled and that event is ticked.

**Workflows:** a successful directory sign-in raises Orchard's `UserLoggedInEvent` once.
