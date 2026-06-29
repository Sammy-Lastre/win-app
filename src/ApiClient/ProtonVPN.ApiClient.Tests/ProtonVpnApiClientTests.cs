using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ProtonVPN.ApiClient.Tests;

[TestClass]
public sealed class ProtonVpnApiClientTests
{
    [TestMethod]
    public async Task GetCurrentUserAsync_AddsRequiredProtonHeaders()
    {
        RecordingHandler handler = new("""{"Code":1000,"User":{"ID":"u1","Name":"test-user"}}""");
        ProtonVpnApiClient client = CreateClient(handler);
        client.UseSession(new ProtonVpnSession("uid", "access", "refresh"));

        UserResponse user = await client.GetCurrentUserAsync();

        user.Name.Should().Be("test-user");
        handler.Requests.Should().ContainSingle();
        HttpRequestMessage request = handler.Requests[0];
        request.RequestUri!.PathAndQuery.Should().Be("/core/v4/users");
        request.Headers.GetValues("x-pm-apiversion").Should().Contain("3");
        request.Headers.GetValues("x-pm-appversion").Should().Contain("windows-vpn@4.4.1+net10");
        request.Headers.GetValues("x-pm-uid").Should().Contain("uid");
        request.Headers.Authorization!.Scheme.Should().Be("Bearer");
        request.Headers.Authorization.Parameter.Should().Be("access");
    }

    [TestMethod]
    public async Task CreateUnauthenticatedSessionAsync_SavesSession()
    {
        RecordingHandler handler = new("""{"Code":1000,"UID":"uid","AccessToken":"access","RefreshToken":"refresh"}""");
        ProtonVpnApiClient client = CreateClient(handler);

        await client.CreateUnauthenticatedSessionAsync();

        client.Session.Should().Be(new ProtonVpnSession("uid", "access", "refresh"));
        handler.Requests[0].RequestUri!.PathAndQuery.Should().Be("/auth/v4/sessions");
    }

    [TestMethod]
    public async Task GetServersAsync_UsesModernLogicalServersEndpoint()
    {
        RecordingHandler handler = new("""{"Code":1000,"LogicalServers":[{"ID":"server1","Name":"JP-FREE#1","Servers":[]}],"StatusID":"status"}""");
        ProtonVpnApiClient client = CreateClient(handler);
        client.UseSession(new ProtonVpnSession("uid", "access", "refresh"));

        ServersResponse servers = await client.GetServersAsync(new ServersQuery(IncludeIds: ["server1"]));

        servers.Servers.Should().ContainSingle(s => s.Id == "server1");
        handler.Requests[0].RequestUri!.PathAndQuery.Should().Contain("/vpn/v2/logicals?");
        handler.Requests[0].RequestUri!.Query.Should().Contain("WithEntriesForProtocols=");
        handler.Requests[0].RequestUri!.Query.Should().Contain("IncludeID[]=");
    }

    [TestMethod]
    public async Task AuthorizedRequest_RefreshesSessionOnceOnUnauthorized()
    {
        QueueResponseHandler handler = new(
            new(HttpStatusCode.Unauthorized, """{"Code":401,"Error":"expired"}"""),
            new(HttpStatusCode.OK, """{"Code":1000,"AccessToken":"new-access","RefreshToken":"new-refresh"}"""),
            new(HttpStatusCode.OK, """{"Code":1000,"User":{"ID":"u1","Name":"test-user"}}"""));
        ProtonVpnApiClient client = CreateClient(handler);
        client.UseSession(new ProtonVpnSession("uid", "old-access", "old-refresh"));

        UserResponse user = await client.GetCurrentUserAsync();

        user.UserId.Should().Be("u1");
        client.Session.Should().Be(new ProtonVpnSession("uid", "new-access", "new-refresh"));
        handler.Requests.Select(r => r.RequestUri!.PathAndQuery)
            .Should().Equal("/core/v4/users", "/auth/refresh", "/core/v4/users");
        handler.Requests[2].Headers.Authorization!.Parameter.Should().Be("new-access");
    }

    [TestMethod]
    public async Task SignInAsync_ThrowsWhenNativeSrpLibraryIsMissing()
    {
        QueueResponseHandler handler = new(
            new(HttpStatusCode.OK, """{"Code":1000,"UID":"uid","AccessToken":"access","RefreshToken":"refresh"}"""),
            new(HttpStatusCode.OK, """{"Code":1000,"Modulus":"m","ServerEphemeral":"s","Version":4,"Salt":"salt","SRPSession":"session"}"""));
        ProtonVpnApiClient client = CreateClient(handler, new NativeSrpProofGenerator());

        Func<Task> act = () => client.SignInAsync("user@example.test", "not-used-in-unit-test");

        await act.Should().ThrowAsync<ProtonVpnSrpUnavailableException>();
    }

    private static ProtonVpnApiClient CreateClient(HttpMessageHandler handler, ISrpProofGenerator? srpProofGenerator = null)
    {
        HttpClient httpClient = new(handler) { BaseAddress = new Uri("https://vpn-api.proton.me/") };
        ProtonVpnApiClientOptions options = new()
        {
            AppVersion = "windows-vpn@4.4.1+net10",
            UserAgent = "ProtonVPN.ApiClient.Tests/1.0.0"
        };

        return new ProtonVpnApiClient(
            httpClient,
            srpProofGenerator ?? new StaticSrpProofGenerator(),
            Options.Create(options),
            NullLogger<ProtonVpnApiClient>.Instance);
    }

    private sealed class StaticSrpProofGenerator : ISrpProofGenerator
    {
        public SrpProof GenerateProof(string password, AuthInfoResponse authInfo)
            => new("client-ephemeral", "client-proof", "server-proof");
    }

    private sealed class RecordingHandler(string responseJson) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(Clone(request));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseJson, Encoding.UTF8, "application/json"),
                RequestMessage = request
            });
        }
    }

    private sealed class QueueResponseHandler(params (HttpStatusCode StatusCode, string Json)[] responses) : HttpMessageHandler
    {
        private readonly Queue<(HttpStatusCode StatusCode, string Json)> _responses = new(responses);

        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(Clone(request));
            (HttpStatusCode statusCode, string json) = _responses.Dequeue();
            return Task.FromResult(new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
                RequestMessage = request
            });
        }
    }

    private static HttpRequestMessage Clone(HttpRequestMessage request)
    {
        HttpRequestMessage clone = new(request.Method, request.RequestUri);
        foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }
}
