# Third-party notices

Tor is MIT licensed (see `LICENSE`). It is distributed as source only: this repository contains no third-party code. Building it downloads the NuGet packages below from nuget.org; each is under its own licence.

The list is every package in the restore of the module (`src/Tor/packages.lock.json`) and the test project (`tests/Tor.Tests/packages.lock.json`) for `net10.0`, with the licence each package declares in its own package metadata. "Module" means the package is part of the module's build; "Tests only" means only the test project uses it. The module also uses the `Microsoft.AspNetCore.App` shared framework that ships with .NET (MIT).

Note on SixLabors.ImageSharp: the module does not reference it directly. It comes with Orchard Core's `OrchardCore.Media` package (through `SixLabors.ImageSharp.Web`), and `Directory.Packages.props` holds it at 3.1.12. The module's picture upload on the account page (`src/Tor/Account/PictureProcessor.cs`) uses it. Its Six Labors Split License grants Apache-2.0 only in the cases it lists; read the licence in the package before you build or ship.

| Package | Version | Licence | Dependency | Used by |
|---|---|---|---|---|
| AnyAscii | 0.3.3 | ISC | Transitive | Module |
| Azure.Core | 1.53.0 | MIT | Transitive | Module |
| Azure.Identity | 1.21.0 | MIT | Transitive | Module |
| Castle.Core | 5.2.1 | Apache-2.0 | Transitive | Module |
| Dapper.StrongName | 2.1.66 | Apache-2.0 | Transitive | Module |
| Fluid.Core | 2.31.0 | MIT | Transitive | Module |
| GraphQL | 8.8.4 | MIT | Transitive | Module |
| GraphQL.Analyzers | 8.8.4 | MIT | Transitive | Module |
| GraphQL.DataLoader | 8.8.4 | MIT | Transitive | Module |
| GraphQL-Parser | 9.5.0 | MIT | Transitive | Module |
| Json.More.Net | 2.2.0 | MIT | Transitive | Module |
| JsonPath.Net | 2.2.0 | MIT | Transitive | Module |
| Microsoft.AspNetCore.Authorization | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.AspNetCore.Metadata | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.AspNetCore.Mvc.Razor.Extensions | 6.0.0 | MIT | Transitive | Module |
| Microsoft.AspNetCore.Mvc.Razor.RuntimeCompilation | 10.0.8 | MIT | Transitive | Module |
| Microsoft.AspNetCore.Razor.Language | 6.0.0 | MIT | Transitive | Module |
| Microsoft.Bcl.AsyncInterfaces | 10.0.3 | MIT | Transitive | Module |
| Microsoft.Bcl.Cryptography | 9.0.4 | MIT | Transitive | Module |
| Microsoft.CodeAnalysis.Analyzers | 5.3.0 | MIT | Transitive | Module |
| Microsoft.CodeAnalysis.Common | 5.3.0 | MIT | Transitive | Module |
| Microsoft.CodeAnalysis.CSharp | 5.3.0 | MIT | Transitive | Module |
| Microsoft.CodeAnalysis.Razor | 6.0.0 | MIT | Transitive | Module |
| Microsoft.CodeCoverage | 18.0.1 | MIT | Transitive | Tests only |
| Microsoft.Data.SqlClient | 6.1.0 | MIT | Transitive | Module |
| Microsoft.Data.SqlClient.SNI.runtime | 6.0.2 | Microsoft Software License Terms (Microsoft.Data.SqlClient.SNI library) | Transitive | Module |
| Microsoft.Data.Sqlite | 10.0.8 | MIT | Transitive | Module |
| Microsoft.Data.Sqlite.Core | 10.0.8 | MIT | Transitive | Module |
| Microsoft.Extensions.Caching.Abstractions | 9.0.4 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Caching.Memory | 9.0.4 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Configuration | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Configuration.Abstractions | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Configuration.Binder | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.DependencyInjection.Abstractions | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.DependencyModel | 10.0.8 | MIT | Transitive | Module |
| Microsoft.Extensions.Diagnostics | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Diagnostics.Abstractions | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.FileProviders.Abstractions | 10.0.3 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Hosting.Abstractions | 10.0.3 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Logging.Abstractions | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Options | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Options.ConfigurationExtensions | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Extensions.Primitives | 10.0.8 | MIT | Transitive | Tests only |
| Microsoft.Identity.Client | 4.83.1 | MIT | Transitive | Module |
| Microsoft.Identity.Client.Extensions.Msal | 4.83.1 | MIT | Transitive | Module |
| Microsoft.IdentityModel.Abstractions | 8.18.0 | MIT | Transitive | Module |
| Microsoft.IdentityModel.JsonWebTokens | 8.18.0 | MIT | Transitive | Module |
| Microsoft.IdentityModel.Logging | 8.18.0 | MIT | Transitive | Module |
| Microsoft.IdentityModel.Protocols | 8.18.0 | MIT | Transitive | Module |
| Microsoft.IdentityModel.Protocols.OpenIdConnect | 8.18.0 | MIT | Transitive | Module |
| Microsoft.IdentityModel.Tokens | 8.18.0 | MIT | Transitive | Module |
| Microsoft.IO.RecyclableMemoryStream | 3.0.1 | MIT | Transitive | Module |
| Microsoft.NET.Test.Sdk | 18.0.1 | MIT | Direct | Tests only |
| Microsoft.SqlServer.Server | 1.0.0 | MIT | Transitive | Module |
| Microsoft.TestPlatform.ObjectModel | 18.0.1 | MIT | Transitive | Tests only |
| Microsoft.TestPlatform.TestHost | 18.0.1 | MIT | Transitive | Tests only |
| MySqlConnector | 2.4.0 | MIT | Transitive | Module |
| Newtonsoft.Json | 13.0.3 | MIT | Transitive | Tests only |
| Npgsql | 9.0.3 | PostgreSQL | Transitive | Module |
| OrchardCore.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Admin.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Apis.GraphQL.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.AuditTrail.Abstractions | 3.0.1 | BSD-3-Clause | Direct | Module |
| OrchardCore.ContentFields.Core | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.ContentManagement | 3.0.1 | BSD-3-Clause | Direct | Module |
| OrchardCore.ContentManagement.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.ContentManagement.Display | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.ContentManagement.GraphQL | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.ContentPreview.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Contents.Core | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.ContentTypes.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Data | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Data.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Data.YesSql | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Data.YesSql.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Deployment.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.DisplayManagement | 3.0.1 | BSD-3-Clause | Direct | Module |
| OrchardCore.DisplayManagement.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.DisplayManagement.Liquid | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.DynamicCache.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.FileStorage.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.FileStorage.FileSystem | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Indexing.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Infrastructure.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Liquid.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Localization.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Media | 3.0.1 | BSD-3-Clause | Direct | Module |
| OrchardCore.Media.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Media.Core | 3.0.1 | BSD-3-Clause | Direct | Module |
| OrchardCore.MetaWeblog.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Module.Targets | 3.0.1 | BSD-3-Clause | Direct | Module |
| OrchardCore.Mvc.Core | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Navigation.Core | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Recipes.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.ResourceManagement | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.ResourceManagement.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.ResourceManagement.Core | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Roles.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Roles.Core | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Shortcodes.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Users.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| OrchardCore.Users.Core | 3.0.1 | BSD-3-Clause | Direct | Module |
| OrchardCore.Workflows.Abstractions | 3.0.1 | BSD-3-Clause | Direct | Module |
| OrchardCore.XmlRpc.Abstractions | 3.0.1 | BSD-3-Clause | Transitive | Module |
| Parlot | 1.5.7 | BSD-3-Clause | Transitive | Module |
| Shortcodes | 1.3.6 | MIT | Transitive | Module |
| SixLabors.ImageSharp | 3.1.12 | Six Labors Split License 1.0 (Apache-2.0 for the cases it lists, otherwise a commercial licence) | Transitive (pinned) | Module |
| SixLabors.ImageSharp.Web | 3.2.0 | Six Labors Split License 1.0 (Apache-2.0 for the cases it lists, otherwise a commercial licence) | Transitive | Module |
| SQLitePCLRaw.bundle_e_sqlite3 | 2.1.11 | Apache-2.0 | Transitive | Module |
| SQLitePCLRaw.core | 2.1.11 | Apache-2.0 | Transitive | Module |
| SQLitePCLRaw.lib.e_sqlite3 | 3.50.3 | Apache-2.0 (stated in the package README; the nuspec names no licence) | Transitive | Module |
| SQLitePCLRaw.provider.e_sqlite3 | 2.1.11 | Apache-2.0 | Transitive | Module |
| System.ClientModel | 1.10.0 | MIT | Transitive | Module |
| System.Configuration.ConfigurationManager | 9.0.4 | MIT | Transitive | Module |
| System.Diagnostics.EventLog | 9.0.4 | MIT | Transitive | Tests only |
| System.DirectoryServices.Protocols | 10.0.14 | MIT | Direct | Module |
| System.IdentityModel.Tokens.Jwt | 8.18.0 | MIT | Transitive | Module |
| System.IO.Hashing | 10.0.8 | MIT | Transitive | Module |
| System.Memory.Data | 10.0.3 | MIT | Transitive | Module |
| System.Security.Cryptography.Pkcs | 10.0.13 | MIT | Transitive (pinned) | Module |
| System.Security.Cryptography.ProtectedData | 9.0.4 | MIT | Transitive | Module |
| TimeZoneConverter | 7.2.0 | MIT | Transitive | Module |
| xunit | 2.9.3 | Apache-2.0 | Direct | Tests only |
| xunit.abstractions | 2.0.3 | Apache-2.0 (licence URL in the nuspec) | Transitive | Tests only |
| xunit.analyzers | 1.18.0 | Apache-2.0 | Transitive | Tests only |
| xunit.assert | 2.9.3 | Apache-2.0 | Transitive | Tests only |
| xunit.core | 2.9.3 | Apache-2.0 | Transitive | Tests only |
| xunit.extensibility.core | 2.9.3 | Apache-2.0 | Transitive | Tests only |
| xunit.extensibility.execution | 2.9.3 | Apache-2.0 | Transitive | Tests only |
| xunit.runner.visualstudio | 3.1.5 | Apache-2.0 | Direct | Tests only |
| YesSql | 5.4.7 | MIT | Transitive | Module |
| YesSql.Abstractions | 5.4.7 | MIT | Transitive | Module |
| YesSql.Core | 5.4.7 | MIT | Transitive | Module |
| YesSql.Filters.Abstractions | 5.4.7 | MIT | Transitive | Module |
| YesSql.Filters.Query | 5.4.7 | MIT | Transitive | Module |
| YesSql.Provider.MySql | 5.4.7 | MIT | Transitive | Module |
| YesSql.Provider.PostgreSql | 5.4.7 | MIT | Transitive | Module |
| YesSql.Provider.Sqlite | 5.4.7 | MIT | Transitive | Module |
| YesSql.Provider.SqlServer | 5.4.7 | MIT | Transitive | Module |
| ZString | 2.6.0 | MIT | Transitive | Module |
