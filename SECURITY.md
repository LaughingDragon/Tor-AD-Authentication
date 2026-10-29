# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting for this
repository: open the repository's **Security** tab and choose **Report a vulnerability**.

Please do not open a public issue, discussion or pull request for a vulnerability. Include what you
can of: the affected feature (Tor sign-in or Tor Account), the version or commit, the configuration
involved (with your own values replaced by examples), and the steps to reproduce.

Reports are answered as time allows; there is no guaranteed response time and no bug bounty.

## Supported versions

Only the latest commit on the `main` branch is supported. Fixes are made there; there are no
back-ported releases.

| Component | Supported |
|---|---|
| `main` branch (0.1.0-preview) | Yes |
| Any older commit or copy | No |
| Orchard Core 3.0.1 on .NET 10 | The only combination built and tested |
| Other Orchard Core or .NET versions | Not tested |

## Scope

In scope: the code in this repository (the `Tor` and `Tor.Account` features and their tests).

Out of scope: Orchard Core itself, .NET, Active Directory and the third-party packages listed in
`NOTICE.md`. Please report those to their own maintainers; for Orchard Core, follow its security
policy at https://github.com/OrchardCMS/OrchardCore/blob/main/SECURITY.md. Known advisories for packages this
project depends on (for example SixLabors.ImageSharp) are already shown by `dotnet restore` with
NuGet audit enabled.
