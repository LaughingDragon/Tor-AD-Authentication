# Contributing

Thank you for helping. Tor is a small, security-sensitive module: it handles domain passwords. Changes are
reviewed with that in mind, and small, focused pull requests are much easier to accept than large ones.

## Security problems

Do not open an issue or pull request for a vulnerability. Use GitHub's private vulnerability reporting, as
described in [`SECURITY.md`](SECURITY.md).

## Before you start

- Open an issue first for anything beyond a small fix, so the approach can be agreed before you write it.
- Tor is built and tested only with Orchard Core 3.0.1 on .NET 10. Say if you tested anything else.
- No test may contact a real domain controller unless it is in `DomainIntegrationTests.cs`, which is skipped
  when its Credential Manager entries are absent.

## Building and testing

```
dotnet restore Tor.slnx --locked-mode
dotnet build Tor.slnx
dotnet test Tor.slnx
```

Package versions are pinned centrally in `Directory.Packages.props`, and the lock files are committed. If you
change a package, run `dotnet restore --force-evaluate`, commit the updated `packages.lock.json` files, and
check `dotnet list Tor.slnx package --vulnerable --include-transitive`.

## Rules for changes

- Follow the existing style (see `.editorconfig`): file-scoped namespaces, the MIT header on every file, short
  comments that say why rather than what.
- Never add a password, token, key, connection string, host name, user name or any other site-specific value,
  including in tests, comments and examples. Use `example.com`, `corp.example.com` and `CORP`.
- Keep every sign-in failure identical to the user: the same message, status and redirect.
- Never log, return or store a password. Typed text that reaches a log goes through `SignInAudit.Clean`.
- Escape every user-controlled value that reaches an LDAP filter with `DirectoryAuthenticator.Escape`.
- Pin any new GitHub Action to a full commit SHA, with the release in a comment.
- Add or update tests for what you change, and update `README.md` and `CHANGELOG.md` when behaviour or settings
  change.
- The pull request template has a security checklist; please work through it.

## Licence

By contributing you agree that your contribution is licensed under the MIT License of this repository
([`LICENSE`](LICENSE)).
