# Changelog

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
