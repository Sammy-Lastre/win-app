using System.Net;

namespace ProtonVPN.ApiClient;

public sealed class ProtonVpnApiException : HttpRequestException
{
    public ProtonVpnApiException(HttpStatusCode? statusCode, int? protonCode, string message)
        : base(message, null, statusCode)
    {
        ProtonCode = protonCode;
    }

    public int? ProtonCode { get; }
}

public sealed class ProtonVpnSrpUnavailableException : InvalidOperationException
{
    public ProtonVpnSrpUnavailableException(Exception innerException)
        : base("The Proton SRP native runtime library is unavailable. Add proton_srp_cffi for the current runtime or replace ISrpProofGenerator.", innerException)
    {
    }
}
