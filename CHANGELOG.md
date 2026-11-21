# Changelog

## 0.1.0-preview.1 (not yet released)

Fixes from the line-by-line security review of 0.1.0-preview, and packaging.

- **Package:** published as `LaughingDragon.OrchardCore.ActiveDirectory`, with symbols, SourceLink
  and no local build paths in the assembly or the symbols. The manifest version is now the package
  version.
- **Documentation:** the README describes the package, and that this version has one feature
  (Tor Account) that holds both the sign-in and the account page. Configuration examples use
  neutral group and role names.
- **No caching of account responses:** every response from `/account`, the pictures included, is
  sent with `Cache-Control: private, no-store` (the pictures were `private, no-cache`).
- **Login password limit:** a password longer than 256 characters (the limit the account forms
  already had) is refused and counted as a failure before the throttle and the bind.
- **Return address:** Tor now uses ASP.NET Core's own local-URL rule, so `~//host`, `~/\host` and
  addresses with control characters send the user to the site root instead of causing an error
  after a successful sign-in.
- **Log text:** typed names in `Tor.Audit` and in Orchard's failure event also lose Unicode line and
  paragraph separators and format characters (for example U+2028, U+202E and zero-width spaces).

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
