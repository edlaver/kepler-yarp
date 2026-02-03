using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

builder.Services.Configure<ProxyOptions>(builder.Configuration.GetSection(ProxyOptions.SectionName));

builder.Services.AddHttpClient(TokenService.HttpClientName);
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton<IForwarderHttpClientFactory, ProxyForwarderHttpClientFactory>();

builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms<DynamicModelTransformProvider>();

builder.WebHost.UseUrls("http://localhost:4000");

var app = builder.Build();

app.MapReverseProxy();

app.Run();

internal sealed class ProxyOptions
{
    public const string SectionName = "Proxy";

    public bool ConvertToken { get; init; }

    public string TokenEndpoint { get; init; } = "https://nwgateway-appdev.kepler-prod.shared.banksvcs.net/token";

    public Dictionary<string, ProviderOptions> Providers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

internal sealed class ProviderOptions
{
    public string RoutePrefix { get; init; } = string.Empty;
    public string UpstreamTemplate { get; init; } = string.Empty;
    public string DefaultModel { get; init; } = string.Empty;
}

internal sealed class DynamicModelTransformProvider : ITransformProvider
{
    private const string OpenAiProviderKey = "openai";

    private readonly IOptionsMonitor<ProxyOptions> _options;

    public DynamicModelTransformProvider(IOptionsMonitor<ProxyOptions> options)
    {
        _options = options;
    }

    public void Apply(TransformBuilderContext context)
    {
        var options = _options.CurrentValue;
        if (!options.Providers.TryGetValue(OpenAiProviderKey, out var provider))
        {
            return;
        }

        if (!string.Equals(context.Route.RouteId, "openai_route", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(provider.RoutePrefix) || string.IsNullOrWhiteSpace(provider.UpstreamTemplate))
        {
            return;
        }

        context.AddPathRemovePrefix(provider.RoutePrefix);
        context.AddRequestTransform(async transformContext =>
        {
            if (transformContext.HttpContext.Request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                transformContext.ProxyRequest.Options.Set(TokenRefreshHandler.OriginalAuthKey, authHeader.ToString());
            }

            var model = await TryGetModelAsync(transformContext.HttpContext.Request).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(model))
            {
                model = provider.DefaultModel;
            }

            if (string.IsNullOrWhiteSpace(model))
            {
                return;
            }

            transformContext.DestinationPrefix = provider.UpstreamTemplate.Replace("{model}", model, StringComparison.OrdinalIgnoreCase);
        });
    }

    public void ValidateCluster(TransformClusterValidationContext context)
    {
    }

    public void ValidateRoute(TransformRouteValidationContext context)
    {
    }

    private static async Task<string?> TryGetModelAsync(HttpRequest request)
    {
        if (request.ContentLength == 0)
        {
            return null;
        }

        if (request.ContentType is null || !request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        request.EnableBuffering();

        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body).ConfigureAwait(false);
            if (!document.RootElement.TryGetProperty("model", out var modelProperty))
            {
                return null;
            }

            if (modelProperty.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            return modelProperty.GetString();
        }
        catch (JsonException)
        {
            return null;
        }
        finally
        {
            if (request.Body.CanSeek)
            {
                request.Body.Position = 0;
            }
        }
    }
}

internal sealed class ProxyForwarderHttpClientFactory : IForwarderHttpClientFactory
{
    private readonly TokenService _tokenService;
    private readonly IOptionsMonitor<ProxyOptions> _options;

    public ProxyForwarderHttpClientFactory(TokenService tokenService, IOptionsMonitor<ProxyOptions> options)
    {
        _tokenService = tokenService;
        _options = options;
    }

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        var socketsHandler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        };

        var tokenHandler = new TokenRefreshHandler(_tokenService, _options)
        {
            InnerHandler = socketsHandler
        };

        return new HttpMessageInvoker(tokenHandler, disposeHandler: true);
    }
}

internal sealed class TokenRefreshHandler : DelegatingHandler
{
    internal static readonly HttpRequestOptionsKey<string> OriginalAuthKey = new("OriginalAuthorization");

    private readonly TokenService _tokenService;
    private readonly IOptionsMonitor<ProxyOptions> _options;

    public TokenRefreshHandler(TokenService tokenService, IOptionsMonitor<ProxyOptions> options)
    {
        _tokenService = tokenService;
        _options = options;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var options = _options.CurrentValue;
        if (!options.ConvertToken)
        {
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        request.Options.TryGetValue(OriginalAuthKey, out var originalAuth);
        if (string.IsNullOrWhiteSpace(originalAuth))
        {
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        if (request.Content is not null)
        {
            await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
        }

        await ApplyTokenAsync(request, originalAuth, forceRefresh: false, cancellationToken).ConfigureAwait(false);

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized && response.StatusCode != HttpStatusCode.Forbidden)
        {
            return response;
        }

        response.Dispose();

        await ApplyTokenAsync(request, originalAuth, forceRefresh: true, cancellationToken).ConfigureAwait(false);

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task ApplyTokenAsync(HttpRequestMessage request, string originalAuth, bool forceRefresh, CancellationToken cancellationToken)
    {
        var token = await _tokenService.GetTokenAsync(originalAuth, forceRefresh, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}

internal sealed class TokenService
{
    public const string HttpClientName = "token-service";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly ConcurrentDictionary<string, TokenCacheEntry> _cache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.Ordinal);

    public TokenService(IHttpClientFactory httpClientFactory, IOptionsMonitor<ProxyOptions> options)
    {
        _httpClientFactory = httpClientFactory;
        _options = options;
    }

    public async Task<string?> GetTokenAsync(string originalAuth, bool forceRefresh, CancellationToken cancellationToken)
    {
        if (!forceRefresh && _cache.TryGetValue(originalAuth, out var existing) && !string.IsNullOrWhiteSpace(existing.Token))
        {
            return existing.Token;
        }

        var gate = _locks.GetOrAdd(originalAuth, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (!forceRefresh && _cache.TryGetValue(originalAuth, out existing) && !string.IsNullOrWhiteSpace(existing.Token))
            {
                return existing.Token;
            }

            var token = await RequestTokenAsync(originalAuth, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(token))
            {
                return null;
            }

            _cache[originalAuth] = new TokenCacheEntry(token, DateTimeOffset.UtcNow);
            return token;
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<string?> RequestTokenAsync(string originalAuth, CancellationToken cancellationToken)
    {
        var options = _options.CurrentValue;
        if (string.IsNullOrWhiteSpace(options.TokenEndpoint))
        {
            return null;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, options.TokenEndpoint);
        request.Headers.TryAddWithoutValidation("Authorization", originalAuth);

        var client = _httpClientFactory.CreateClient(HttpClientName);
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(content))
        {
            return null;
        }

        if (response.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)
        {
            try
            {
                using var document = JsonDocument.Parse(content);
                var root = document.RootElement;
                if (TryReadToken(root, "token", out var token) ||
                    TryReadToken(root, "access_token", out token) ||
                    TryReadToken(root, "accessToken", out token))
                {
                    return token;
                }
            }
            catch (JsonException)
            {
            }
        }

        return content.Trim();
    }

    private static bool TryReadToken(JsonElement root, string propertyName, out string? token)
    {
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String)
        {
            token = property.GetString();
            return !string.IsNullOrWhiteSpace(token);
        }

        token = null;
        return false;
    }

    private sealed record TokenCacheEntry(string Token, DateTimeOffset LastUpdated);
}
