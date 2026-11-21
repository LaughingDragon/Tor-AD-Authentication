# Threat model

This is the threat model for Tor 0.1.0-preview: the **Tor** sign-in feature and the **Tor Account** feature.
It describes what Tor protects, where the trust boundaries are, which attackers it considers, how each threat
is handled and what risk remains. The last section maps Tor's controls to OWASP ASVS 4.0.3 level 2. That table
shows where the design is **aligned with** ASVS. It is not a certification or a claim of compliance, and the
gaps are listed.

Code locations are given as `file:line` in this release.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Domain passwords | Typed on the login form and the account forms; held in memory for one request only | A stolen password opens the user's whole domain account, not just this site |
| The bound user's directory object | Active Directory | The account page writes `unicodePwd`, `thumbnailPhoto`, `telephoneNumber`, `mobile`, `physicalDeliveryOfficeName` |
| Orchard sign-in cookie | The browser; protected by ASP.NET Core Data Protection keys on the server | Whoever holds it is the user on this site until it expires |
| Role mapping (`GroupRoles`, `AllowAdministratorMapping`) | Server configuration | A wrong entry can make directory users Orchard administrators |
| The break-glass local account | Orchard user store; its name in `LocalAccounts` | The way in when the domain is down; a high-value target |
| Directory snapshot | Orchard user document (`DirectoryProfile`) | Personal data: phone numbers, office, groups, managed computers, photo |
| Site picture | Orchard Media library, `site-profile/{user id}/{random}.jpg` | A personal photo |
| Audit records | `Tor.Audit` log; Orchard Audit Trail | Evidence of who signed in or changed what |

## Trust boundaries

1. **Browser to web server.** Everything in the request is untrusted: the form fields, the query string (`returnUrl`), the headers (including `X-Forwarded-For`) and the uploaded files.
2. **Web server to domain controllers.** LDAPS on port 636 with Negotiate, bound as the user. The domain controller's certificate is validated by the operating system's TLS stack, and its name must match the configured server name. Values read back from the directory are trusted for identity (SID, `sAMAccountName`, `tokenGroups`) but are length-capped before they are stored or shown.
3. **Tor to Orchard Core.** Tor runs inside the Orchard tenant and trusts Orchard's anti-forgery check, user store, role service, login-form events and cookie handling.
4. **Server configuration.** `OrchardCore:Tor` in the site's settings is trusted. Whoever can edit it controls who can sign in and with which roles.

## Attackers

- **A: anonymous internet or network attacker.** Can reach the login page and send any request. Wants to guess passwords, find valid names, lock users out, cause a redirect off-site or exhaust the server.
- **B: signed-in user.** Has a valid session. Wants to act on another user's account, raise their own roles, upload something harmful, or reach another user's data.
- **C: someone with a stolen session cookie.** Wants to change the victim's domain password or details without knowing the password.
- **D: man in the middle between the web server and a domain controller.** Wants to read passwords or forge directory answers.
- **E: someone who can read the server's logs or Audit Trail but not the configuration.** Wants passwords or forged entries.

Out of scope: an attacker with administrator access to the web server, the Orchard admin or a domain controller; flaws in Orchard Core, .NET, Windows or Active Directory themselves.

## Threats and mitigations

### Login path

| Threat | Attacker | Mitigation | Evidence |
|---|---|---|---|
| LDAP filter injection through the user name | A | User input is never put into a filter or a DN. The bind uses the typed name only as a credential; the filters use the identity returned by WhoAmI and the configured group names, and every value is escaped per RFC 4515. | `Directory/DirectoryAuthenticator.cs:149,264,304,365` |
| Malformed or oversized names | A | Names are trimmed, limited to 256 characters (20 for a `sAMAccountName`) and refused if they contain a control character or a character AD forbids, before any directory call. | `Directory/AccountName.cs:36-90` |
| Password guessing | A | Per-name and per-address throttle (5 and 20 failures in 15 minutes by default). Blocked attempts do not reach the domain, so they stop adding to the domain's own lockout count. | `Services/LoginThrottle.cs` |
| Telling causes apart (valid name, disabled, not in group, two-factor) | A | Every directory failure gives the same message ("Invalid login attempt."), status and redirect. The cause goes only to `Tor.Audit`. | `Filters/DirectoryLoginFilter.cs:301-319` |
| Off-site redirect after sign-in | A | `returnUrl` is used only when it is a local path; ASP.NET Core's `LocalRedirectResult` checks it again. | `Filters/DirectoryLoginFilter.cs:132,316` |
| Spoofed client address | A | Tor uses `HttpContext.Connection.RemoteIpAddress` and never reads `X-Forwarded-For` itself. Forwarded headers count only if the host application configures ASP.NET Core's forwarded-headers middleware with known proxies. | `Filters/DirectoryLoginFilter.cs:84` |
| Password exposure in transit to the domain | D | LDAPS (TLS) is the default; the certificate is validated by the OS, with no callback that accepts any certificate. The non-default LDAP mode uses Negotiate signing and sealing, and the password change refuses to run in that mode. | `Directory/DirectoryAuthenticator.cs:100-127`; `Directory/DirectoryWriter.cs:47` |
| Password exposure in logs, events or errors | E | Passwords are never passed to a logger, an event or a message. Exceptions are logged by type name only, and typed names are cleaned of control characters and capped at 128 characters. | `Services/SignInAudit.cs:42-45`; `Filters/DirectoryLoginFilter.cs:135-141` |
| Forged log lines | A, E | Control characters (CR, LF and the rest) are removed from typed text, which is cut to 128 characters. | `Services/SignInAudit.cs:42-45` |
| Taking over a local account | A | Directory users are matched by SID only. A new directory user whose name already belongs to an unlinked Orchard user is refused. | `Services/DirectoryUserSync.cs:108-111` |
| Granting administrator by accident | Configuration | `GroupRoles` is empty by default; Administrator, or the role Orchard reports as its admin role, is refused unless `AllowAdministratorMapping` is set; roles that do not exist are not created. | `Services/DirectoryUserSync.cs:79-101` |
| Skipping Orchard's own checks | A | After the bind, Tor runs Orchard's checks in Orchard's order: login-form events, enabled, lockout, `CanSignInAsync`, `ValidatingLoginAsync`. Two-factor users are refused rather than let through without the second factor. | `Filters/DirectoryLoginFilter.cs:168-216` |
| Unexpected errors | A | Any unexpected exception in a directory sign-in fails closed with the generic answer. | `Filters/DirectoryLoginFilter.cs:135-141` |

### Account path (`/account`)

| Threat | Attacker | Mitigation | Evidence |
|---|---|---|---|
| Acting on another user's account | B | No route or form takes a user id or name; every action uses the signed-in user, and every directory write checks that the bound account's SID is the SID linked to that user. | `Controllers/AccountController.cs:465-489`; `Directory/DirectoryWriter.cs:122-128` |
| Cross-site request forgery | B, C | Every POST requires Orchard's anti-forgery token. | `Controllers/AccountController.cs:130,189,294,371,436` |
| Changing the domain password or details with a stolen cookie | C | Every directory action binds with the current password typed on the form. | `Controllers/AccountController.cs:140,217,304` |
| Guessing the current password through the account forms | C | The three directory actions share one budget of 3 attempts per user in 15 minutes. | `Controllers/AccountController.cs:154,252,337` |
| Writing an attribute that is not meant to be writable | B | Writes are limited to an allow-list of four attributes plus the password. | `Directory/DirectoryWriter.cs:39-42,62` |
| Showing typed values back | B | Forms post and redirect back to `/account`; typed values are never rendered. | `Controllers/AccountController.cs:460-463` |

### Upload path (domain picture and site picture)

| Threat | Attacker | Mitigation | Evidence |
|---|---|---|---|
| Oversized uploads | B | Request and multipart limits of 2 MB + 64 KB on the action, then a 2 MB check before decoding. | `Controllers/AccountController.cs:190-191,225`; `Account/PictureProcessor.cs:62` |
| Disguised file types, SVG with script | B | Only JPEG and PNG pass, by file signature. The decoder loads only the JPEG and PNG modules, so decoding decides the type; SVG, GIF, WebP and anything else are refused. | `Account/PictureProcessor.cs:42-50,67` |
| Decompression bombs | B | The header's dimensions are checked first: at most 12,000 pixels a side and 40 million pixels, one frame. | `Account/PictureProcessor.cs:74-78` |
| Metadata leaks (GPS, camera), ICC parser flaws | B | Metadata is not parsed at all, and the output is a new JPEG with every profile cleared. | `Account/PictureProcessor.cs:49,85-93` |
| User-chosen file names and paths | B | Stored as `site-profile/{user id letters and digits}/{32 random hex}.jpg`; the stored path is used only if it is inside the user's own folder. | `Account/SitePictureStore.cs:104-113` |

## Residual risks

These remain in 0.1.0-preview. The D-040 security review (in the project's private records) rates each one and proposes a fix.

1. **Anyone can lock out a named user for the window.** Five failures for a name, from any address, block that name for 15 minutes, and continued failures also count towards the domain's own lockout. This is the price of per-name throttling.
2. **The break-glass account answers differently.** A failed break-glass sign-in gets Orchard's own response (the login page re-rendered, status 200), while every directory failure is a redirect (302). An attacker can therefore tell whether a name is a break-glass account.
3. **The throttle is in memory and per process.** A restart clears it, several servers count separately, and its table is pruned of expired windows only. There is no hard cap on entries or key length while windows are live.
4. **A user principal name is a separate throttle key** from the plain and `DOMAIN\` forms of the same account, so one person can get more than five tries per window.
5. **The throttle check and the failure count are not atomic.** Parallel attempts can exceed the limit slightly.
6. **There is no absolute session lifetime.** The cookie has an 8-hour sliding expiry, so an active session never ends by itself, and disabling a user in the directory does not end their Orchard session.
7. **The login password has no length limit before the bind** (the account forms do: 256 characters).
8. **Options are not validated at start-up.** For example, a zero or negative `FailureWindowMinutes` switches the throttle off.
9. **Picture responses are `private, no-cache`, not `no-store`**, and the account page sets no cache header of its own.
10. **Site pictures are in the Media library.** Unless the site protects media (for example with Orchard's Secure Media feature), anyone who learns a picture's random address can fetch it.
11. **Inherited package advisories.** SixLabors.ImageSharp 3.1.12 (through OrchardCore.Media 3.0.1) and MySqlConnector 2.4.0 (through YesSql) have published advisories. Tor's own decoding uses only the JPEG and PNG decoders with metadata skipped, which avoids the affected code paths. The fixed ImageSharp versions come under a different licence.
12. **Unicode line separators and bidirectional controls** (U+2028, U+2029, U+202E) are not removed from logged names. They do not break log lines, but they can mislead some log viewers.

## OWASP ASVS 4.0.3 level 2

The table shows where the design is **aligned with** ASVS 4.0.3 level 2, where it is partly aligned, and where it is not. It is a self-assessment, not a certification.

| ASVS | Requirement (short) | Tor | Status |
|---|---|---|---|
| V2.2.1 | Anti-automation against credential attacks | Per-name and per-address throttle, below the domain's lockout | Aligned, with residual risks 1, 3, 4 and 5 |
| V2.2.2 | Weak authenticators limited | Not applicable: authentication is the domain password; policy is the domain's | N/A |
| V2.1.1-V2.1.9 | Password length, composition and change rules | Delegated to the domain's password policy; the change form asks for the current password | Aligned through the domain |
| V2.1.6 | Password change requires the current password | `ChangeOwnDomainPassword` binds with the current password | Aligned |
| V3.2.1 | New session token at authentication | Orchard's `SignInManager` issues a new cookie | Aligned |
| V3.3.1 | Logout invalidates the session | Orchard's sign-out; security stamp validation | Aligned |
| V3.3.2 | Re-authentication after an absolute period (12 hours at L2) | 8-hour sliding expiry only | **Not aligned** (residual risk 6) |
| V3.4.1-3 | Cookie `Secure`, `HttpOnly`, `SameSite` | Set while Tor is on | Aligned |
| V3.7.1 | Re-authentication before sensitive actions | Every directory action requires the current password | Aligned |
| V4.1.1, V4.2.1 | Access control enforced on the server; no direct object references | No user id or name taken from the request; SID check on every write | Aligned |
| V4.2.2 | Anti-CSRF | Anti-forgery on every POST | Aligned |
| V5.1.3, V5.1.4 | Input validated by allow-list, length and type | Names, phones, location choices, attribute allow-list | Aligned, except residual risk 7 |
| V5.1.5 | Redirects only to allow-listed destinations | Local `returnUrl` only | Aligned |
| V5.3.7 | Protection against LDAP injection | RFC 4515 escaping; no user input in a DN | Aligned |
| V7.1.1 | No credentials in logs | Never logged; tested | Aligned |
| V7.3.1 | Log injection prevented | Control characters removed, length capped | Aligned, with residual risk 12 |
| V7.4.1 | Generic error message | One answer for every sign-in failure | Partly aligned (residual risk 2) |
| V8.2.1 | Anti-caching headers on sensitive data | `private, no-cache` on pictures | **Partly aligned** (residual risk 9) |
| V8.3.4 | Sensitive data identified and protected | Snapshot capped and stored on the user; photo private to the user | Aligned, with residual risk 10 |
| V9.2.1 | Connections to servers use trusted TLS certificates | LDAPS validated by the OS, name matched | Aligned |
| V9.2.2 | Encrypted connections to back-end systems | LDAPS default; LDAP mode signed and sealed | Aligned |
| V12.1.1 | File size limits | 2 MB, before decoding | Aligned |
| V12.2.1 | Files checked to be of the expected type | Signature and decoding, JPEG and PNG only | Aligned |
| V12.3.1 | User-supplied file names not used | Random file names in the user's own folder | Aligned |
| V12.4.1 | Untrusted files stored outside the web root | Media library | **Partly aligned** (residual risk 10) |
| V12.5.2 | Uploaded files never executed | Re-encoded JPEG served as `image/jpeg` with `nosniff` | Aligned |
| V14.2.1 | Components up to date, without known vulnerabilities | Inherited advisories in ImageSharp and MySqlConnector | **Not aligned** (residual risk 11) |
| V14.4.3 | `X-Content-Type-Options: nosniff` | On the picture responses | Aligned |
| (no single ASVS 4 item) | Configuration validated at start-up, secure defaults | Secure defaults; no start-up validation | **Partly aligned** (residual risk 8) |
