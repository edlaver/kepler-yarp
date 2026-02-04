using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
builder.Services.AddSingleton<DebugLogger>();

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

    public string? DebugPath { get; init; }

    public Dictionary<string, ProviderOptions> Providers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

internal sealed class ProviderOptions
{
    public string RoutePrefix { get; init; } = string.Empty;
    public string UpstreamTemplate { get; init; } = string.Empty;
    public string DefaultModel { get; init; } = string.Empty;
    public Dictionary<string, string> ModelAliases { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public bool DisableStreaming { get; init; }
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

            var request = transformContext.HttpContext.Request;
            var model = await TryGetModelAsync(request).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(model))
            {
                model = provider.DefaultModel;
            }

            if (string.IsNullOrWhiteSpace(model))
            {
                return;
            }

            if (provider.ModelAliases.TryGetValue(model, out var aliasTarget) && !string.IsNullOrWhiteSpace(aliasTarget))
            {
                model = aliasTarget;
                await TryUpdateModelAsync(request, model).ConfigureAwait(false);
            }
            else if (!string.IsNullOrWhiteSpace(provider.DefaultModel) && !string.Equals(model, provider.DefaultModel, StringComparison.Ordinal))
            {
                await TryUpdateModelAsync(request, model).ConfigureAwait(false);
            }

            if (provider.DisableStreaming && request.Path.Value?.EndsWith("/chat/completions", StringComparison.OrdinalIgnoreCase) == true)
            {
                await TryUpdateStreamAsync(request).ConfigureAwait(false);
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

    private static async Task TryUpdateModelAsync(HttpRequest request, string model)
    {
        if (request.ContentLength == 0)
        {
            return;
        }

        if (request.ContentType is null || !request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        request.EnableBuffering();

        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body).ConfigureAwait(false);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            var json = JsonNode.Parse(document.RootElement.GetRawText()) as JsonObject;
            if (json is null)
            {
                return;
            }

            json["model"] = model;

            var updated = json.ToJsonString();
            var bytes = Encoding.UTF8.GetBytes(updated);
            request.Body = new MemoryStream(bytes);
            request.ContentLength = bytes.Length;
            request.Body.Position = 0;
        }
        catch (JsonException)
        {
        }
        finally
        {
            if (request.Body.CanSeek)
            {
                request.Body.Position = 0;
            }
        }
    }

    private static async Task TryUpdateStreamAsync(HttpRequest request)
    {
        if (request.ContentLength == 0)
        {
            return;
        }

        if (request.ContentType is null || !request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        request.EnableBuffering();

        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body).ConfigureAwait(false);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            var json = JsonNode.Parse(document.RootElement.GetRawText()) as JsonObject;
            if (json is null)
            {
                return;
            }

            json["stream"] = false;

            var updated = json.ToJsonString();
            var bytes = Encoding.UTF8.GetBytes(updated);
            request.Body = new MemoryStream(bytes);
            request.ContentLength = bytes.Length;
            request.Body.Position = 0;
        }
        catch (JsonException)
        {
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
    private readonly DebugLogger _debugLogger;
    private readonly IOptionsMonitor<ProxyOptions> _options;

    public ProxyForwarderHttpClientFactory(TokenService tokenService, DebugLogger debugLogger, IOptionsMonitor<ProxyOptions> options)
    {
        _tokenService = tokenService;
        _debugLogger = debugLogger;
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

        var tokenHandler = new TokenRefreshHandler(_tokenService, _debugLogger, _options)
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
    private readonly DebugLogger _debugLogger;
    private readonly IOptionsMonitor<ProxyOptions> _options;

    public TokenRefreshHandler(TokenService tokenService, DebugLogger debugLogger, IOptionsMonitor<ProxyOptions> options)
    {
        _tokenService = tokenService;
        _debugLogger = debugLogger;
        _options = options;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var options = _options.CurrentValue;
        if (!options.ConvertToken)
        {
            await _debugLogger.LogRequestAsync(request, cancellationToken).ConfigureAwait(false);
            var responseMessage = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            await _debugLogger.LogResponseAsync(request, responseMessage, cancellationToken).ConfigureAwait(false);
            return responseMessage;
        }

        request.Options.TryGetValue(OriginalAuthKey, out var originalAuth);
        if (string.IsNullOrWhiteSpace(originalAuth))
        {
            await _debugLogger.LogRequestAsync(request, cancellationToken).ConfigureAwait(false);
            var responseMessage = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            await _debugLogger.LogResponseAsync(request, responseMessage, cancellationToken).ConfigureAwait(false);
            return responseMessage;
        }

        if (request.Content is not null)
        {
            await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
        }

        await ApplyTokenAsync(request, originalAuth, forceRefresh: false, cancellationToken).ConfigureAwait(false);

        await _debugLogger.LogRequestAsync(request, cancellationToken).ConfigureAwait(false);
        var forwardResponse = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await _debugLogger.LogResponseAsync(request, forwardResponse, cancellationToken).ConfigureAwait(false);
        if (forwardResponse.StatusCode != HttpStatusCode.Unauthorized && forwardResponse.StatusCode != HttpStatusCode.Forbidden)
        {
            return forwardResponse;
        }

        forwardResponse.Dispose();

        await ApplyTokenAsync(request, originalAuth, forceRefresh: true, cancellationToken).ConfigureAwait(false);

        await _debugLogger.LogRequestAsync(request, cancellationToken).ConfigureAwait(false);
        var retryResponse = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await _debugLogger.LogResponseAsync(request, retryResponse, cancellationToken).ConfigureAwait(false);
        return retryResponse;
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

internal sealed class DebugLogger
{
    private static long _sequence;
    private readonly IOptionsMonitor<ProxyOptions> _options;

    public DebugLogger(IOptionsMonitor<ProxyOptions> options)
    {
        _options = options;
    }

    public Task LogRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => LogAsync(request, response: null, "request", cancellationToken);

    public Task LogResponseAsync(HttpRequestMessage request, HttpResponseMessage response, CancellationToken cancellationToken)
        => LogAsync(request, response, "response", cancellationToken);

    private async Task LogAsync(HttpRequestMessage request, HttpResponseMessage? response, string suffix, CancellationToken cancellationToken)
    {
        var debugPath = _options.CurrentValue.DebugPath;
        if (string.IsNullOrWhiteSpace(debugPath))
        {
            return;
        }

        Directory.CreateDirectory(debugPath);

        var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss-fffffff");
        var sequence = Interlocked.Increment(ref _sequence);
        var fileName = $"{timestamp}-{sequence:D4}-{suffix}.md";
        var filePath = Path.Combine(debugPath, fileName);

        var builder = new StringBuilder();
        if (suffix == "request")
        {
            builder.AppendLine("# Request");
            builder.AppendLine();
            builder.AppendLine($"**Method**: {request.Method}");
            builder.AppendLine($"**Uri**: {request.RequestUri}");
            builder.AppendLine();
            AppendHeaders(builder, request.Headers, request.Content?.Headers);

            var payloadBytes = await ReadContentBytesAsync(request.Content, cancellationToken).ConfigureAwait(false);
            if (payloadBytes is not null)
            {
                ReplaceRequestContent(request, payloadBytes);
                builder.AppendLine();
                builder.AppendLine("```json");
                builder.AppendLine(Encoding.UTF8.GetString(payloadBytes));
                builder.AppendLine("```");
            }
        }
        else
        {
            builder.AppendLine("# Response");
            builder.AppendLine();
            builder.AppendLine($"**Status**: {(int)response!.StatusCode} {response.StatusCode}");
            builder.AppendLine($"**Uri**: {request.RequestUri}");
            builder.AppendLine();
            AppendHeaders(builder, response.Headers, response.Content?.Headers);

            var payloadBytes = await ReadContentBytesAsync(response.Content, cancellationToken).ConfigureAwait(false);
            if (payloadBytes is not null)
            {
                ReplaceResponseContent(response, payloadBytes);
                builder.AppendLine();
                builder.AppendLine("```json");
                builder.AppendLine(Encoding.UTF8.GetString(payloadBytes));
                builder.AppendLine("```");
            }
        }

        await File.WriteAllTextAsync(filePath, builder.ToString(), Encoding.UTF8, cancellationToken).ConfigureAwait(false);
    }

    private static void AppendHeaders(StringBuilder builder, HttpHeaders headers, HttpHeaders? contentHeaders)
    {
        builder.AppendLine("| Header | Value |");
        builder.AppendLine("| --- | --- |");
        foreach (var header in headers)
        {
            builder.AppendLine($"| {header.Key} | {string.Join(", ", header.Value)} |");
        }

        if (contentHeaders is null)
        {
            return;
        }

        foreach (var header in contentHeaders)
        {
            builder.AppendLine($"| {header.Key} | {string.Join(", ", header.Value)} |");
        }
    }

    private static async Task<byte[]?> ReadContentBytesAsync(HttpContent? content, CancellationToken cancellationToken)
    {
        if (content is null)
        {
            return null;
        }

        var bytes = await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (bytes.Length == 0)
        {
            return null;
        }
        return bytes;
    }

    private static void ReplaceRequestContent(HttpRequestMessage request, byte[] bytes)
    {
        if (request.Content is null)
        {
            return;
        }

        var originalHeaders = request.Content.Headers;
        var replacement = new ByteArrayContent(bytes);
        foreach (var header in originalHeaders)
        {
            replacement.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        request.Content = replacement;
    }

    private static void ReplaceResponseContent(HttpResponseMessage response, byte[] bytes)
    {
        if (response.Content is null)
        {
            return;
        }

        var originalHeaders = response.Content.Headers;
        var replacement = new ByteArrayContent(bytes);
        foreach (var header in originalHeaders)
        {
            replacement.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        response.Content = replacement;
    }
}
