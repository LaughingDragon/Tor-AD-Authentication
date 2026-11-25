# Changelog

## 1.0.0 (unreleased)

The first stable release. Settings from 0.1.0-preview.1 load unchanged; no setting, default, feature
id or permission changes.

- **Compatibility promise:** within 1.x, setting keys, their defaults and ranges, the feature ids,
  permission names and the `Tor.Audit` log texts only change in a new major version; anything to be
  removed is marked deprecated here at least one minor release before. Everything covered is listed
  in the new `docs/CONFIGURATION.md`. Tests check that 0.1.0-preview.1 settings still load, that the
  defaults are the documented ones, and that the reference lists every setting.
- **ImageSharp 3.2.1:** SixLabors.ImageSharp, which comes with Orchard's Media package, is now held at
  3.2.1 instead of 3.1.12. This fixes the six advisories published for 3.1.12 (four rated High by
  NuGet audit), none of which Tor's own picture code reached (it decodes JPEG and PNG only, without
  metadata); Orchard's Media pipeline on the same site uses ImageSharp with its default formats.
  It stays a transitive dependency, so no Six Labors licence key is needed to build Tor or a site
  that uses it.
- **Supported versions:** `SECURITY.md` and the README state what is supported (the latest 1.x) and
  what was tested.
- **Group matching:** the check of the user's token against the managed groups is now a separate
  function, with tests for nested groups, long group lists (3,000 groups in the token) and more mapped
  groups than the account page shows (the page shows 50; every mapped group still counts). No change
  in behaviour.
- **Version:** the package, the assembly and the Orchard manifest are 1.0.0.

## 0.1.0-preview.1 (2026-11-25)

Fixes from the line-by-line security review of 0.1.0-preview, which has been done, and packaging.
The risks that remain are listed in `THREAT-MODEL.md` (Residual risks).

- **Package:** published as `LaughingDragon.OrchardCore.ActiveDirectory`, with symbols, SourceLink
  and no local build paths in the assembly or the symbols. The manifest version is now the package
  version.
- **Features:** the module now declares a **Tor** feature for the directory sign-in, and **Tor
  Account** (the account page) depends on it. Before, the module declared only Tor Account, so Orchard
  never created **Tor** and put the sign-in under Tor Account. Sites that had Tor Account enabled get
  **Tor** enabled with it as its dependency.
- **Start-up log:** the number of local (break-glass) accounts configured, never their names, is
  written to `Tor.Audit` at start-up, with a warning when `LocalAccounts` is empty.
- **Documentation:** the README describes the package and its two features. Configuration examples
  use neutral group and role names.
- **No caching of account responses:** every response from `/account`, the pictures included, is
  sent with `Cache-Control: private, no-store` (the pictures were `private, no-cache`).
- **Login password limit:** a password longer than 256 characters (the limit the account forms
  already had) is refused and counted as a failure before the throttle and the bind.
- **Return address:** Tor now uses ASP.NET Core's own local-URL rule, so `~//host`, `~/\host` and
  addresses with control characters send the user to the site root instead of causing an error
  after a successful sign-in.
- **Log text:** typed names in `Tor.Audit` and in Orchard's failure event also lose Unicode line and
  paragraph separators and format characters (for example U+2028, U+202E and zero-width spaces).
- **Settings are checked:** an empty `Domain`, `NetBiosName` or `Servers`, a `TimeoutSeconds` outside
  1 to 60, or a limit or window below 1 is logged as an error at start-up, and every directory sign-in
  is then refused (not counted against the user) until it is fixed. The throttle no longer switches
  off with a zero or negative window. A warning is logged at start-up when `UseLdaps` is `false`.
- **Picture size:** uploads are limited to 16 million pixels (was 40 million), which caps the
  memory one decode can take at about 64 MB. The 2 MB and 12,000-pixel limits are unchanged.
- **Throttle:** a user principal name with the configured domain now shares the count of the plain
  and `DOMAIN\` forms of the same account. An attempt is checked and counted in one step, so
  parallel attempts no longer pass the limit. Keys are hashed (bounded whatever was typed), the
  table has a hard cap of 50,000 windows, and a full table no longer costs a scan on every failure.
- **Break-glass answer:** a refused break-glass sign-in now gets the same answer as a refused
  directory sign-in ("Invalid login attempt." and a redirect to the login page) instead of Orchard's
  login page with its own message, so a break-glass name can no longer be told apart.
- **Absolute session lifetime:** every sign-in now ends 12 hours after it was made (setting
  `MaxSessionHours`, 1 to 720), however often it is used; the 8-hour sliding expiry still applies
  within it. Cookies issued before the upgrade count from when they were last issued. Users are
  signed out when their session reaches the limit.
- **Status text and threat model:** the README, the threat model and its ASVS table describe this
  release; the residual risks are listed in `THREAT-MODEL.md`.

## 0.1.0-preview

First public preview. Changes from the earlier, unpublished versions of Tor:

- **Role mapping:** the default `GroupRoles` map is empty, so every group must be mapped explicitly.
  Mapping a group to `Administrator` (or to Orchard's admin role) works only when the new setting
  `AllowAdministratorMapping` is `true`; otherwise the entry is ignored with a warning. Mapped roles
  that do not exist in Orchard are not granted. The effective mapping is logged at start-up.
- **Orchard's login checks and events:** a directory sign-in now follows Orchard's own login.
  `LoggingInAsync` is raised before any directory call, and an error from it stops the sign-in.
  Orchard's checks on the user apply (enabled, lockout, `CanSignInAsync`, `ValidatingLoginAsync`).
  `LoggingInFailedAsync` is raised once on every failure. `LoggedInAsync` and the
  `UserLoggedInEvent` workflow event are raised once on success. Every failure gets the same
  answer, and unexpected errors fail closed.
- **Two-factor:** directory users with Orchard two-factor authentication turned on, or required for
  them, are refused.
- **Audit:** failed directory sign-ins are recorded in Orchard's Audit Trail as "Login failed" when
  that event is ticked in the Audit Trail settings.
- **ImageSharp:** the module no longer references SixLabors.ImageSharp directly; it comes with
  Orchard's `OrchardCore.Media` package (held at 3.1.12).
- **Neutral examples:** configuration examples and test data use example values only, and the
  account page's Location choices are optional and configurable.
