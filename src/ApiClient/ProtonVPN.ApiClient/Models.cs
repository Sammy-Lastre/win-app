using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProtonVPN.ApiClient;

public sealed record ProtonVpnApiClientOptions
{
    public Uri BaseAddress { get; set; } = new("https://vpn-api.proton.me/");
    public string ApiVersion { get; set; } = "3";
    public string AppVersion { get; set; } = "windows-vpn@4.4.1+net10";
    public string UserAgent { get; set; } = "ProtonVPN.ApiClient/1.0.0";
    public string Locale { get; set; } = "en_US";
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(60);
}

public sealed record ProtonVpnSession(
    [property: JsonPropertyName("UID")] string UniqueSessionId,
    string AccessToken,
    string RefreshToken);

public sealed record ServersQuery(
    bool SecureCore = true,
    bool IncludeState = true,
    IReadOnlyCollection<string>? IncludeIds = null,
    string ProtocolEntries = "WireGuardUDP,WireGuardTCP,WireGuardTLS,OpenVPNUDP,OpenVPNTCP");

public sealed record SrpProof(string ClientEphemeral, string ClientProof, string ExpectedServerProof);

public class ProtonResponse
{
    public const int OkCode = 1000;
    public int Code { get; set; }
    public string? Error { get; set; }
    public ProtonResponseDetails? Details { get; set; }
}

public sealed class ProtonResponseDetails
{
    public string? Description { get; set; }
    public string? Title { get; set; }
    public string? Body { get; set; }
    public IReadOnlyList<string>? HumanVerificationMethods { get; set; }
    public string? HumanVerificationToken { get; set; }
}

public sealed class AuthInfoRequest
{
    public required string Username { get; init; }
    public string Intent { get; init; } = "Proton";
}

public sealed class AuthInfoResponse : ProtonResponse
{
    public string? Modulus { get; set; }
    public string? ServerEphemeral { get; set; }
    public int Version { get; set; }
    public string? Salt { get; set; }
    [JsonPropertyName("SRPSession")]
    public string? SrpSession { get; set; }
    [JsonPropertyName("SSOChallengeToken")]
    public string? SsoChallengeToken { get; set; }
}

public sealed class AuthRequest
{
    public required string Username { get; init; }
    public required string ClientEphemeral { get; init; }
    public required string ClientProof { get; init; }
    [JsonPropertyName("SRPSession")]
    public required string SrpSession { get; init; }
}

public class SessionResponse : ProtonResponse
{
    [JsonPropertyName("UID")]
    public string? UniqueSessionId { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
}

public sealed class UnauthSessionResponse : SessionResponse;

public sealed class AuthResponse : SessionResponse
{
    [JsonPropertyName("UserID")]
    public string? UserId { get; set; }
    public string? Scope { get; set; }
    public string? ServerProof { get; set; }
    [JsonPropertyName("2FA")]
    public TwoFactorAuthResponse? TwoFactor { get; set; }
}

public sealed class TwoFactorAuthResponse
{
    public int Enabled { get; set; }
}

public sealed class TwoFactorRequest
{
    [JsonPropertyName("TwoFactorCode")]
    public required string Code { get; init; }
}

public sealed class RefreshTokenRequest
{
    public string GrantType { get; init; } = "refresh_token";
    public required string RefreshToken { get; init; }
    public string RedirectUri { get; init; } = "https://vpn-api.proton.me";
    public string ResponseType { get; init; } = "token";
}

public sealed class RefreshTokenResponse : ProtonResponse
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
}

public sealed class UserEnvelopeResponse : ProtonResponse
{
    public UserResponse? User { get; set; }
}

public sealed class UserResponse
{
    [JsonPropertyName("ID")]
    public string? UserId { get; set; }
    public string? Name { get; set; }
    public string? DisplayName { get; set; }
    public string? Email { get; set; }
    public long CreateTime { get; set; }
}

public sealed class VpnInfoEnvelopeResponse : ProtonResponse
{
    [JsonPropertyName("VPN")]
    public VpnInfoResponse? Vpn { get; set; }
    public int Services { get; set; }
    public int Subscribed { get; set; }
}

public sealed class VpnInfoResponse
{
    public string? PlanName { get; set; }
    public string? PlanTitle { get; set; }
    public int Status { get; set; }
    public sbyte MaxTier { get; set; }
    public int MaxConnect { get; set; }
    [JsonPropertyName("GroupID")]
    public string? GroupId { get; set; }
    public bool IsBusiness { get; set; }
}

public sealed class DeviceLocationResponse : ProtonResponse
{
    [JsonPropertyName("IP")]
    public string? Ip { get; set; }
    [JsonPropertyName("ISP")]
    public string? Isp { get; set; }
    public string? Country { get; set; }
    public double Latitude { get; set; }
    public double Longitude { get; set; }
}

public sealed class ServersResponse : ProtonResponse
{
    [JsonPropertyName("LogicalServers")]
    public IReadOnlyList<LogicalServerResponse> Servers { get; set; } = [];
    [JsonPropertyName("StatusID")]
    public string? StatusId { get; set; }
}

public sealed class LogicalServerResponse
{
    [JsonPropertyName("ID")]
    public string? Id { get; set; }
    public string? Name { get; set; }
    public string? EntryCountry { get; set; }
    public string? ExitCountry { get; set; }
    public string? Domain { get; set; }
    public sbyte Tier { get; set; }
    public ulong Features { get; set; }
    public sbyte Status { get; set; }
    public sbyte Load { get; set; }
    [JsonIgnore]
    public IReadOnlyList<PhysicalServerResponse> PhysicalServers { get; set; } = [];
    [JsonPropertyName("Servers")]
    public IReadOnlyList<PhysicalServerResponse> Servers { get => PhysicalServers; set => PhysicalServers = value; }
}

public sealed class PhysicalServerResponse
{
    [JsonPropertyName("ID")]
    public string? Id { get; set; }
    [JsonPropertyName("EntryIP")]
    public string? EntryIp { get; set; }
    public string? Domain { get; set; }
    public sbyte Status { get; set; }
    public string? Label { get; set; }
    public string? X25519PublicKey { get; set; }
    public string? Signature { get; set; }
}

public sealed class ServerCountResponse : ProtonResponse
{
    public int Servers { get; set; }
    public int Countries { get; set; }
}

public sealed class VpnConfigResponse : ProtonResponse
{
    public int? ServerRefreshInterval { get; set; }
    public int ChangeServerAttemptLimit { get; set; }
    public int ChangeServerShortDelayInSeconds { get; set; }
    public int ChangeServerLongDelayInSeconds { get; set; }
    public JsonElement? DefaultPorts { get; set; }
    public JsonElement? FeatureFlags { get; set; }
    public JsonElement? SmartProtocol { get; set; }
}

[JsonSerializable(typeof(AuthInfoRequest))]
[JsonSerializable(typeof(AuthRequest))]
[JsonSerializable(typeof(TwoFactorRequest))]
[JsonSerializable(typeof(RefreshTokenRequest))]
[JsonSerializable(typeof(ProtonResponse))]
[JsonSerializable(typeof(AuthInfoResponse))]
[JsonSerializable(typeof(AuthResponse))]
[JsonSerializable(typeof(UnauthSessionResponse))]
[JsonSerializable(typeof(RefreshTokenResponse))]
[JsonSerializable(typeof(UserEnvelopeResponse))]
[JsonSerializable(typeof(VpnInfoEnvelopeResponse))]
[JsonSerializable(typeof(DeviceLocationResponse))]
[JsonSerializable(typeof(ServersResponse))]
[JsonSerializable(typeof(ServerCountResponse))]
[JsonSerializable(typeof(VpnConfigResponse))]
internal sealed partial class ProtonVpnJsonContext : JsonSerializerContext;
