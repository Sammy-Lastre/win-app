namespace ProtonVPN.ApiClient;

public interface IProtonVpnApiClient
{
    ProtonVpnSession? Session { get; }
    void UseSession(ProtonVpnSession session);
    void ClearSession();
    Task<UnauthSessionResponse> CreateUnauthenticatedSessionAsync(CancellationToken cancellationToken = default);
    Task<AuthResponse> SignInAsync(string username, string password, CancellationToken cancellationToken = default);
    Task CompleteTotpTwoFactorAsync(string code, CancellationToken cancellationToken = default);
    Task<RefreshTokenResponse> RefreshSessionAsync(CancellationToken cancellationToken = default);
    Task<UserResponse> GetCurrentUserAsync(CancellationToken cancellationToken = default);
    Task<VpnInfoResponse> GetVpnInfoAsync(CancellationToken cancellationToken = default);
    Task<DeviceLocationResponse> GetLocationAsync(CancellationToken cancellationToken = default);
    Task<ServersResponse> GetServersAsync(ServersQuery? query = null, CancellationToken cancellationToken = default);
    Task<ServerCountResponse> GetServerCountAsync(CancellationToken cancellationToken = default);
    Task<VpnConfigResponse> GetVpnConfigAsync(CancellationToken cancellationToken = default);
    Task<byte[]> GetServerStatusBinaryAsync(string statusId, CancellationToken cancellationToken = default);
}

public interface ISrpProofGenerator
{
    SrpProof GenerateProof(string password, AuthInfoResponse authInfo);
}
