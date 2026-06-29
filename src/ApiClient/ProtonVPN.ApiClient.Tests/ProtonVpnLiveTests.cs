using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ProtonVPN.ApiClient.Tests;

[TestClass]
public sealed class ProtonVpnLiveTests
{
    [TestMethod]
    public async Task FreeAccount_CanAuthenticateAndReadCoreVpnData_WhenCredentialsAndSrpRuntimeAreConfigured()
    {
        string? username = Environment.GetEnvironmentVariable("PROTONVPN_TEST_USERNAME");
        string? password = Environment.GetEnvironmentVariable("PROTONVPN_TEST_PASSWORD");

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            Assert.Inconclusive("Set PROTONVPN_TEST_USERNAME and PROTONVPN_TEST_PASSWORD to run live Proton VPN API tests.");
        }

        ServiceProvider services = new ServiceCollection()
            .AddLogging()
            .AddProtonVpnApiClient(options =>
            {
                options.AppVersion = "windows-vpn@4.4.1+net10";
                options.UserAgent = "ProtonVPN.ApiClient.Tests/1.0.0";
            })
            .BuildServiceProvider();

        IProtonVpnApiClient client = services.GetRequiredService<IProtonVpnApiClient>();

        try
        {
            AuthResponse auth = await client.SignInAsync(username, password);
            if (auth.TwoFactor?.Enabled is > 0)
            {
                Assert.Inconclusive("The configured Proton account requires two-factor authentication.");
            }
        }
        catch (ProtonVpnSrpUnavailableException ex)
        {
            Assert.Inconclusive(ex.Message);
        }

        UserResponse user = await client.GetCurrentUserAsync();
        VpnInfoResponse vpn = await client.GetVpnInfoAsync();
        DeviceLocationResponse? location = null;
        ProtonVpnApiException? locationException = null;
        try
        {
            location = await client.GetLocationAsync();
        }
        catch (ProtonVpnApiException ex) when (ex.Message.Contains("Location cannot be calculated", StringComparison.OrdinalIgnoreCase))
        {
            locationException = ex;
        }

        ServerCountResponse counts = await client.GetServerCountAsync();
        ServersResponse servers = await client.GetServersAsync();
        VpnConfigResponse config = await client.GetVpnConfigAsync();

        user.UserId.Should().NotBeNullOrWhiteSpace();
        vpn.Status.Should().BeGreaterThanOrEqualTo(0);
        (location?.Ip is not null || locationException is not null).Should().BeTrue();
        counts.Servers.Should().BeGreaterThan(0);
        servers.Servers.Should().NotBeEmpty();
        config.Code.Should().Be(ProtonResponse.OkCode);
    }
}
