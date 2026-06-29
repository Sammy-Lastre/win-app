using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace ProtonVPN.ApiClient;

public static class DependencyInjection
{
    public static IServiceCollection AddProtonVpnApiClient(
        this IServiceCollection services,
        Action<ProtonVpnApiClientOptions>? configure = null)
    {
        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<ISrpProofGenerator, ManagedSrpProofGenerator>();
        services.AddHttpClient<IProtonVpnApiClient, ProtonVpnApiClient>((serviceProvider, client) =>
        {
            ProtonVpnApiClientOptions options = serviceProvider.GetRequiredService<IOptions<ProtonVpnApiClientOptions>>().Value;
            client.BaseAddress = options.BaseAddress;
            client.Timeout = options.Timeout;
        });

        return services;
    }
}
