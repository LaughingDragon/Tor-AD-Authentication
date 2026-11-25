# Threat model

This is the threat model for Tor 1.0.0: the directory sign-in (the **Tor** feature) and the account page
(the **Tor Account** feature, which depends on **Tor**).
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
| Orchard sign-in cookie | The browser; protected by ASP.NET Core Data Protection keys on the server | Whoever holds it is the user on this site until it expires (8 hours idle, at most 12 hours by default) |
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
| Malformed or oversized names and passwords | A | Names are trimmed, limited to 256 characters (20 for a `sAMAccountName`) and refused if they contain a control character or a character AD forbids, before any directory call. A login password longer than 256 characters is refused, and counted, before the throttle and the bind. | `Directory/AccountName.cs:45-97`; `Filters/DirectoryLoginFilter.cs:202` |
| Password guessing | A | Per-name and per-address throttle (5 and 20 failures in 15 minutes by default). `name`, `DOMAIN\name` and `name@domain` (configured domain) share one count. Each attempt is checked and counted in one step under a lock, so parallel attempts cannot pass the limit. Blocked attempts do not reach the domain, so they stop adding to the domain's own lockout count. | `Services/LoginThrottle.cs`; `Directory/AccountName.cs:90`; `Filters/DirectoryLoginFilter.cs:92,209` |
| Exhausting the throttle's memory | A | Keys are SHA-256 hashes, so their size does not depend on what was typed. The table holds at most 50,000 windows; when full, expired windows go first, then the oldest tenth. | `Services/LoginThrottle.cs` |
| Telling causes apart (valid name, disabled, not in group, two-factor, break-glass account) | A | Every directory failure, and every refused break-glass sign-in, gives the same message ("Invalid login attempt."), status and redirect. The cause goes only to `Tor.Audit`. | `Filters/DirectoryLoginFilter.cs:115,336-363` |
| Off-site redirect after sign-in | A | `returnUrl` is used only when it is local by ASP.NET Core's own rule (`Url.IsLocalUrl`); `LocalRedirectResult` checks it again. | `Filters/DirectoryLoginFilter.cs:141,357,388-402` |
| Spoofed client address | A | Tor uses `HttpContext.Connection.RemoteIpAddress` and never reads `X-Forwarded-For` itself. Forwarded headers count only if the host application configures ASP.NET Core's forwarded-headers middleware with known proxies. | `Filters/DirectoryLoginFilter.cs:85` |
| Password exposure in transit to the domain | D | LDAPS (TLS) is the default; the certificate is validated by the OS, with no callback that accepts any certificate. The non-default LDAP mode uses Negotiate signing and sealing, a warning is logged at start-up, and the password change refuses to run in that mode. | `Directory/DirectoryAuthenticator.cs:100-127`; `Directory/DirectoryWriter.cs:47`; `Services/RoleMappingLog.cs` |
| Password exposure in logs, events or errors | E | Passwords are never passed to a logger, an event or a message. Exceptions are logged by type name only. | `Services/SignInAudit.cs`; `Filters/DirectoryLoginFilter.cs:144-150` |
| Forged or misleading log lines | A, E | Control characters (CR, LF and the rest), Unicode line and paragraph separators and format characters (bidirectional overrides, zero-width characters) are removed from typed text, which is cut to 128 characters. | `Services/SignInAudit.cs:44-52` |
| Taking over a local account | A | Directory users are matched by SID only. A new directory user whose name already belongs to an unlinked Orchard user is refused. | `Services/DirectoryUserSync.cs:108-111` |
| Granting administrator by accident | Configuration | `GroupRoles` is empty by default; Administrator, or the role Orchard reports as its admin role, is refused unless `AllowAdministratorMapping` is set; roles that do not exist are not created. | `Services/DirectoryUserSync.cs:79-101` |
| A wrong setting weakening the sign-in | Configuration | Settings are checked (`TorOptionsCheck`): each problem is logged as an error at tenant start, and while any remains every directory sign-in is refused. The throttle never switches off, whatever its settings. Nothing throws, so the break-glass sign-in and the rest of the site keep working. | `Services/TorOptionsCheck.cs`; `Services/RoleMappingLog.cs:30`; `Filters/DirectoryLoginFilter.cs:195` |
| Skipping Orchard's own checks | A | After the bind, Tor runs Orchard's checks in Orchard's order: login-form events, enabled, lockout, `CanSignInAsync`, `ValidatingLoginAsync`. Two-factor users are refused rather than let through without the second factor. | `Filters/DirectoryLoginFilter.cs:187-252` |
| A session that never ends | C | Besides the 8-hour sliding expiry, every sign-in ends `MaxSessionHours` (12 by default) after it was made; the start is kept in the cookie's own properties, so the sliding renewal does not move it. | `Services/SessionLifetime.cs`; `Startup.cs:53` |
| Unexpected errors | A | Any unexpected exception in a directory sign-in fails closed with the generic answer. | `Filters/DirectoryLoginFilter.cs:144-150` |

### Account path (`/account`)

| Threat | Attacker | Mitigation | Evidence |
|---|---|---|---|
| Acting on another user's account | B | No route or form takes a user id or name; every action uses the signed-in user, and every directory write checks that the bound account's SID is the SID linked to that user. | `Controllers/AccountController.cs:464-488`; `Directory/DirectoryWriter.cs:122-128` |
| Cross-site request forgery | B, C | Every POST requires Orchard's anti-forgery token. | `Controllers/AccountController.cs:129,188,293,370,435` |
| Changing the domain password or details with a stolen cookie | C | Every directory action binds with the current password typed on the form. | `Controllers/AccountController.cs:139,216,303` |
| Guessing the current password through the account forms | C | The three directory actions share one budget of 3 attempts per user in 15 minutes. | `Controllers/AccountController.cs:153,251,336` |
| Writing an attribute that is not meant to be writable | B | Writes are limited to an allow-list of four attributes plus the password. | `Directory/DirectoryWriter.cs:39-42,62` |
| Showing typed values back | B | Forms post and redirect back to `/account`; typed values are never rendered. | `Controllers/AccountController.cs:459-462` |
| Account data kept in a browser or proxy cache | B | Every response from `/account`, the pictures included, is `Cache-Control: private, no-store`. | `Controllers/NoStoreAttribute.cs`; `Controllers/AccountController.cs:27` |

### Upload path (domain picture and site picture)

| Threat | Attacker | Mitigation | Evidence |
|---|---|---|---|
| Oversized uploads | B | Request and multipart limits of 2 MB + 64 KB on the action, then a 2 MB check before decoding. | `Controllers/AccountController.cs:189-190,224`; `Account/PictureProcessor.cs:62` |
| Disguised file types, SVG with script | B | Only JPEG and PNG pass, by file signature. The decoder loads only the JPEG and PNG modules, so decoding decides the type; SVG, GIF, WebP and anything else are refused. | `Account/PictureProcessor.cs:42-50,67` |
| Decompression bombs | B | The header's dimensions are checked first: at most 12,000 pixels a side and 16 million pixels (about 64 MB decoded), one frame. | `Account/PictureProcessor.cs:74-78` |
| Metadata leaks (GPS, camera), ICC parser flaws | B | Metadata is not parsed at all, and the output is a new JPEG with every profile cleared. | `Account/PictureProcessor.cs:49,85-93` |
| User-chosen file names and paths | B | Stored as `site-profile/{user id letters and digits}/{32 random hex}.jpg`; the stored path is used only if it is inside the user's own folder. | `Account/SitePictureStore.cs:104-113` |

## Residual risks

These remain in 1.0.0, after the fixes from the line-by-line security review of 0.1.0-preview and the review of 1.0.0.

1. **Anyone can lock out a named user for the window.** Five failures for a name, from any address, block that name for 15 minutes, and continued failures also count towards the domain's own lockout. This is the price of per-name throttling.
2. **The throttle is in memory and per process.** A restart clears it, and several servers count separately. When its table is full (50,000 windows), the oldest windows are dropped, so an attacker with many addresses can make old counts be forgotten sooner.
3. **A user principal name with another suffix** (an alternative UPN suffix of the forest) has its own count, separate from the plain name.
4. **Disabling a user in the directory does not end an Orchard session at once.** The session ends at the latest when the absolute lifetime (12 hours by default) is reached; the next sign-in is refused.
5. **Site pictures are in the Media library.** Unless the site protects media (for example with Orchard's Secure Media feature), anyone who learns a picture's random address can fetch it.
6. **Inherited package advisory.** MySqlConnector 2.4.0 (through YesSql, Orchard Core's data layer) has a published moderate advisory (GHSA-473q-m89c-ghf8). Tor does not use MySQL; the package is only loaded by a site that runs Orchard on MySQL, and the fix belongs to Orchard Core's dependency. SixLabors.ImageSharp is held at 3.2.1, which fixes the six advisories published for 3.1.12 (1.0.0).
7. **Response timing against a real domain was not measured.** With stand-ins every failure cause takes the same time to answer; a real bind that fails may take longer or shorter than a refusal before the bind.

## OWASP ASVS 4.0.3 level 2

The table shows where the design is **aligned with** ASVS 4.0.3 level 2, where it is partly aligned, and where it is not. It is a self-assessment, not a certification.

| ASVS | Requirement (short) | Tor | Status |
|---|---|---|---|
| V2.2.1 | Anti-automation against credential attacks | Per-name and per-address throttle, below the domain's lockout; one count per person; checked and counted in one step; bounded | Aligned, with residual risks 1, 2 and 3 |
| V2.2.2 | Weak authenticators limited | Not applicable: authentication is the domain password; policy is the domain's | N/A |
| V2.1.1-V2.1.9 | Password length, composition and change rules | Delegated to the domain's password policy; the change form asks for the current password | Aligned through the domain |
| V2.1.6 | Password change requires the current password | `ChangeOwnDomainPassword` binds with the current password | Aligned |
| V3.2.1 | New session token at authentication | Orchard's `SignInManager` issues a new cookie | Aligned |
| V3.3.1 | Logout invalidates the session | Orchard's sign-out; security stamp validation | Aligned |
| V3.3.2 | Re-authentication after an absolute period (12 hours at L2) | `MaxSessionHours`, 12 by default, plus the 8-hour sliding expiry | Aligned, with residual risk 4 |
| V3.4.1-3 | Cookie `Secure`, `HttpOnly`, `SameSite` | Set while Tor is on | Aligned |
| V3.7.1 | Re-authentication before sensitive actions | Every directory action requires the current password | Aligned |
| V4.1.1, V4.2.1 | Access control enforced on the server; no direct object references | No user id or name taken from the request; SID check on every write | Aligned |
| V4.2.2 | Anti-CSRF | Anti-forgery on every POST | Aligned |
| V5.1.3, V5.1.4 | Input validated by allow-list, length and type | Names, login password length, phones, location choices, attribute allow-list | Aligned |
| V5.1.5 | Redirects only to allow-listed destinations | Local `returnUrl` only, by ASP.NET Core's rule | Aligned |
| V5.3.7 | Protection against LDAP injection | RFC 4515 escaping; no user input in a DN | Aligned |
| V7.1.1 | No credentials in logs | Never logged; tested | Aligned |
| V7.3.1 | Log injection prevented | Control, separator and format characters removed, length capped | Aligned |
| V7.4.1 | Generic error message | One answer for every sign-in failure, break-glass included | Aligned, with residual risk 7 |
| V8.2.1 | Anti-caching headers on sensitive data | `private, no-store` on every `/account` response | Aligned |
| V8.3.4 | Sensitive data identified and protected | Snapshot capped and stored on the user; photo private to the user | Aligned, with residual risk 5 |
| V9.2.1 | Connections to servers use trusted TLS certificates | LDAPS validated by the OS, name matched | Aligned |
| V9.2.2 | Encrypted connections to back-end systems | LDAPS default; LDAP mode signed and sealed, with a start-up warning | Aligned |
| V12.1.1 | File size limits | 2 MB, before decoding; 16 million pixels | Aligned |
| V12.2.1 | Files checked to be of the expected type | Signature and decoding, JPEG and PNG only | Aligned |
| V12.3.1 | User-supplied file names not used | Random file names in the user's own folder | Aligned |
| V12.4.1 | Untrusted files stored outside the web root | Media library | **Partly aligned** (residual risk 5) |
| V12.5.2 | Uploaded files never executed | Re-encoded JPEG served as `image/jpeg` with `nosniff` | Aligned |
| V14.2.1 | Components up to date, without known vulnerabilities | ImageSharp held at 3.2.1 (advisories fixed); one inherited MySqlConnector advisory | **Partly aligned** (residual risk 6) |
| V14.4.3 | `X-Content-Type-Options: nosniff` | On the picture responses | Aligned |
| (no single ASVS 4 item) | Configuration validated at start-up, secure defaults | Secure defaults; settings checked, directory sign-in fails closed on a problem | Aligned |
