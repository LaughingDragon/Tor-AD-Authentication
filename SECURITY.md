# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting for this
repository: open the repository's **Security** tab and choose **Report a vulnerability**.

Please do not open a public issue, discussion or pull request for a vulnerability. Include what you
can of: the affected feature (Tor sign-in or Tor Account), the version or commit, the configuration
involved (with your own values replaced by examples), and the steps to reproduce.

Reports are answered as time allows; there is no guaranteed response time and no bug bounty.

## Supported versions

The latest 1.x release is supported. Security fixes are released as a new 1.x version (a patch
release, or a minor release when the fix needs a new setting); they are not back-ported to older 1.x
releases. Upgrading within 1.x keeps your settings working (see "Compatibility" below).

| Version | Supported |
|---|---|
| Latest 1.x release (1.0.0) | Yes |
| Older 1.x releases | No: upgrade to the latest 1.x |
| 0.1.0-preview.1 and earlier previews | No: upgrade to 1.x (its settings load unchanged) |
| Orchard Core 3.0.1 on .NET 10 | The only combination built and tested |
| Other Orchard Core or .NET versions | Not tested |

## Compatibility

Within 1.x, setting keys, their defaults and their ranges only change in a new major version, and so
do the feature ids, permission names and the `Tor.Audit` log texts. A setting or behaviour that is to
be removed is marked deprecated in `CHANGELOG.md` at least one minor release before. The full list is
in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

## Scope

In scope: the code in this repository (the `Tor` and `Tor.Account` features and their tests).

Out of scope: Orchard Core itself, .NET, Active Directory and the third-party packages listed in
`NOTICE.md`. Please report those to their own maintainers; for Orchard Core, follow its security
policy at https://github.com/OrchardCMS/OrchardCore/blob/main/SECURITY.md. Known advisories for packages this
project depends on (for example MySqlConnector, through Orchard Core) are already shown by
`dotnet restore` with NuGet audit enabled.
