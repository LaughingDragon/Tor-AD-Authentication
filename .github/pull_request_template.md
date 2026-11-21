## What this changes

<!-- One or two sentences. Link the issue if there is one. Security problems: do not open a pull request; use private vulnerability reporting (see SECURITY.md). -->

## How it was tested

<!-- dotnet test output, and anything checked by hand. Say which Orchard Core and .NET versions. -->

## Security checklist

- [ ] No password, token, key, connection string, host name, user name or other site-specific value is added (code, tests, comments, configuration or screenshots).
- [ ] Every user-controlled value that reaches an LDAP filter is escaped (`DirectoryAuthenticator.Escape`, RFC 4515), and none is used to build a DN.
- [ ] Every sign-in failure still gives the same message, status and redirect, whatever the cause.
- [ ] No password reaches a log line, exception message, model state, URL, cookie, notification or the Audit Trail; typed text in log lines goes through `SignInAudit.Clean`.
- [ ] LDAPS certificate validation is unchanged: no `VerifyServerCertificate` callback, no lower TLS version, no new plain-LDAP path.
- [ ] New account actions take no user id or name from the request, need the anti-forgery token and the current password, and use the shared attempt budget.
- [ ] Uploads keep the size limit before decoding, type by decoding, dimension and frame limits, metadata stripping and re-encoding.
- [ ] Return addresses are accepted only when local.
- [ ] New options have secure defaults and are documented in README.md.
- [ ] No new package, or the new package is pinned in `Directory.Packages.props`, the lock files are updated and `dotnet list package --vulnerable --include-transitive` was checked.
- [ ] Any new GitHub Action is pinned to a full commit SHA with its release in a comment.
- [ ] Tests cover the change, and `dotnet test` passes.
