# ProtonVPN.ApiClient

Standalone .NET 10 API client for Proton VPN.

```csharp
services.AddProtonVpnApiClient();
```

Credentials and tokens are never persisted by the library. Store `ProtonVpnSession`
using your application's credential storage if sessions should survive process
restarts.

Authentication uses Proton SRP through `ISrpProofGenerator`. The default
implementation is managed .NET code and ships in this package. Applications can
replace `ISrpProofGenerator` if they need a different SRP implementation.

Live tests are opt-in:

```powershell
$env:PROTONVPN_TEST_USERNAME = "username"
$env:PROTONVPN_TEST_PASSWORD = "password"
dotnet test src\ApiClient\ProtonVPN.ApiClient.Tests\ProtonVPN.ApiClient.Tests.csproj
```
