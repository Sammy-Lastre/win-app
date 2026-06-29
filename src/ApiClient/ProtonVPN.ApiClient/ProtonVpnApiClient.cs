using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ProtonVPN.ApiClient;

public sealed class ProtonVpnApiClient : IProtonVpnApiClient
{
    private const string LogicalSignServer = "Server.EntryIP,Server.Label";
    private readonly HttpClient _httpClient;
    private readonly ISrpProofGenerator _srpProofGenerator;
    private readonly ProtonVpnApiClientOptions _options;
    private readonly ILogger<ProtonVpnApiClient> _logger;
    private readonly JsonSerializerOptions _jsonOptions;
    private AuthResponse? _pendingTwoFactorAuth;

    public ProtonVpnApiClient(
        HttpClient httpClient,
        ISrpProofGenerator srpProofGenerator,
        IOptions<ProtonVpnApiClientOptions> options,
        ILogger<ProtonVpnApiClient> logger)
    {
        _httpClient = httpClient;
        _srpProofGenerator = srpProofGenerator;
        _options = options.Value;
        _logger = logger;
        _jsonOptions = ProtonVpnJsonContext.Default.Options;
    }

    public ProtonVpnSession? Session { get; private set; }

    public void UseSession(ProtonVpnSession session) => Session = session;

    public void ClearSession()
    {
        Session = null;
        _pendingTwoFactorAuth = null;
    }

    public async Task<UnauthSessionResponse> CreateUnauthenticatedSessionAsync(CancellationToken cancellationToken = default)
    {
        UnauthSessionResponse response = await SendAsync<UnauthSessionResponse>(HttpMethod.Post, "auth/v4/sessions", null, false, cancellationToken);
        SaveSession(response);
        return response;
    }

    public async Task<AuthResponse> SignInAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (Session is null)
        {
            await CreateUnauthenticatedSessionAsync(cancellationToken);
        }

        AuthInfoResponse authInfo = await SendAsync<AuthInfoResponse>(
            HttpMethod.Post,
            "auth/info",
            new AuthInfoRequest { Username = username },
            true,
            cancellationToken);

        SrpProof proof = _srpProofGenerator.GenerateProof(password, authInfo);
        AuthResponse auth = await SendAsync<AuthResponse>(
            HttpMethod.Post,
            "auth",
            new AuthRequest
            {
                Username = username,
                ClientEphemeral = proof.ClientEphemeral,
                ClientProof = proof.ClientProof,
                SrpSession = authInfo.SrpSession ?? throw new ProtonVpnApiException(null, authInfo.Code, "Missing SRP session.")
            },
            true,
            cancellationToken);

        if (!string.Equals(auth.ServerProof, proof.ExpectedServerProof, StringComparison.Ordinal))
        {
            throw new ProtonVpnApiException(null, auth.Code, "Invalid SRP server proof.");
        }

        if (auth.TwoFactor?.Enabled is > 0)
        {
            _pendingTwoFactorAuth = auth;
            return auth;
        }

        SaveSession(auth);
        return auth;
    }

    public async Task CompleteTotpTwoFactorAsync(string code, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        AuthResponse pending = _pendingTwoFactorAuth ?? throw new InvalidOperationException("No two-factor authentication challenge is pending.");

        ProtonVpnSession previous = Session ?? throw new InvalidOperationException("No session is available.");
        Session = new ProtonVpnSession(
            pending.UniqueSessionId ?? previous.UniqueSessionId,
            pending.AccessToken ?? previous.AccessToken,
            pending.RefreshToken ?? previous.RefreshToken);

        await SendAsync<ProtonResponse>(HttpMethod.Post, "auth/v4/2fa", new TwoFactorRequest { Code = code }, true, cancellationToken);
        SaveSession(pending);
        _pendingTwoFactorAuth = null;
    }

    public async Task<RefreshTokenResponse> RefreshSessionAsync(CancellationToken cancellationToken = default)
    {
        ProtonVpnSession current = Session ?? throw new InvalidOperationException("No session is available.");
        RefreshTokenResponse response = await SendAsync<RefreshTokenResponse>(
            HttpMethod.Post,
            "auth/refresh",
            new RefreshTokenRequest { RefreshToken = current.RefreshToken, RedirectUri = _options.BaseAddress.ToString().TrimEnd('/') },
            true,
            cancellationToken,
            retryOnUnauthorized: false);

        Session = new ProtonVpnSession(current.UniqueSessionId, response.AccessToken ?? current.AccessToken, response.RefreshToken ?? current.RefreshToken);
        return response;
    }

    public async Task<UserResponse> GetCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        UserEnvelopeResponse envelope = await SendAsync<UserEnvelopeResponse>(HttpMethod.Get, "core/v4/users", null, true, cancellationToken);
        return envelope.User ?? throw new ProtonVpnApiException(null, envelope.Code, "The user response was empty.");
    }

    public async Task<VpnInfoResponse> GetVpnInfoAsync(CancellationToken cancellationToken = default)
    {
        VpnInfoEnvelopeResponse envelope = await SendAsync<VpnInfoEnvelopeResponse>(HttpMethod.Get, "vpn/v2", null, true, cancellationToken);
        return envelope.Vpn ?? throw new ProtonVpnApiException(null, envelope.Code, "The VPN info response was empty.");
    }

    public Task<DeviceLocationResponse> GetLocationAsync(CancellationToken cancellationToken = default)
        => SendAsync<DeviceLocationResponse>(HttpMethod.Get, "vpn/location", null, false, cancellationToken);

    public Task<ServersResponse> GetServersAsync(ServersQuery? query = null, CancellationToken cancellationToken = default)
    {
        query ??= new ServersQuery();
        StringBuilder uri = new("vpn/v2/logicals");
        uri.Append($"?SignServer={Uri.EscapeDataString(LogicalSignServer)}");
        uri.Append(query.SecureCore ? "&SecureCoreFilter=all" : "&SecureCoreFilter=off");
        uri.Append($"&WithState={query.IncludeState.ToString().ToLowerInvariant()}");
        uri.Append($"&WithEntriesForProtocols={Uri.EscapeDataString(query.ProtocolEntries)}");

        if (query.IncludeIds is not null)
        {
            foreach (string includeId in query.IncludeIds)
            {
                uri.Append("&IncludeID[]=").Append(Uri.EscapeDataString(includeId));
            }
        }

        return SendAsync<ServersResponse>(HttpMethod.Get, uri.ToString(), null, true, cancellationToken);
    }

    public Task<ServerCountResponse> GetServerCountAsync(CancellationToken cancellationToken = default)
        => SendAsync<ServerCountResponse>(HttpMethod.Get, "vpn/servers-count", null, true, cancellationToken);

    public Task<VpnConfigResponse> GetVpnConfigAsync(CancellationToken cancellationToken = default)
        => SendAsync<VpnConfigResponse>(HttpMethod.Get, "vpn/v2/clientconfig", null, true, cancellationToken);

    public async Task<byte[]> GetServerStatusBinaryAsync(string statusId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statusId);
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, $"vpn/v2/status/{Uri.EscapeDataString(statusId)}/binary", true);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new ProtonVpnApiException(response.StatusCode, null, $"Proton VPN API request failed with HTTP {(int)response.StatusCode}.");
        }

        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> SendAsync<T>(
        HttpMethod method,
        string requestUri,
        object? body,
        bool authorize,
        CancellationToken cancellationToken,
        bool retryOnUnauthorized = true)
        where T : ProtonResponse
    {
        using HttpRequestMessage request = CreateRequest(method, requestUri, authorize);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: _jsonOptions);
        }

        using HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized && retryOnUnauthorized && authorize && Session is not null)
        {
            _logger.LogInformation("Refreshing Proton VPN API session after unauthorized response.");
            await RefreshSessionAsync(cancellationToken).ConfigureAwait(false);
            return await SendAsync<T>(method, requestUri, body, authorize, cancellationToken, retryOnUnauthorized: false).ConfigureAwait(false);
        }

        return await ReadResponseAsync<T>(response, cancellationToken).ConfigureAwait(false);
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string requestUri, bool authorize)
    {
        HttpRequestMessage request = new(method, requestUri);
        request.Headers.Add("x-pm-apiversion", _options.ApiVersion);
        request.Headers.Add("x-pm-appversion", _options.AppVersion);
        request.Headers.Add("x-pm-locale", _options.Locale);
        request.Headers.UserAgent.ParseAdd(_options.UserAgent);

        if (authorize)
        {
            ProtonVpnSession session = Session ?? throw new InvalidOperationException("This Proton VPN API endpoint requires a session.");
            request.Headers.Add("x-pm-uid", session.UniqueSessionId);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.AccessToken);
        }

        return request;
    }

    private async Task<T> ReadResponseAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
        where T : ProtonResponse
    {
        string json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            ProtonResponse? protonError = TryDeserialize<ProtonResponse>(json);
            string message = protonError?.Error ?? $"Proton VPN API request failed with HTTP {(int)response.StatusCode}.";
            throw new ProtonVpnApiException(response.StatusCode, protonError?.Code, message);
        }

        T result = JsonSerializer.Deserialize<T>(json, _jsonOptions)
            ?? throw new ProtonVpnApiException(response.StatusCode, null, "The Proton VPN API returned an empty response.");

        if (result.Code != ProtonResponse.OkCode)
        {
            throw new ProtonVpnApiException(response.StatusCode, result.Code, result.Error ?? "The Proton VPN API returned an error.");
        }

        return result;
    }

    private T? TryDeserialize<T>(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json, _jsonOptions);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private void SaveSession(SessionResponse response)
    {
        if (response.UniqueSessionId is null || response.AccessToken is null || response.RefreshToken is null)
        {
            throw new ProtonVpnApiException(null, response.Code, "The session response did not contain complete token data.");
        }

        Session = new ProtonVpnSession(response.UniqueSessionId, response.AccessToken, response.RefreshToken);
    }
}
