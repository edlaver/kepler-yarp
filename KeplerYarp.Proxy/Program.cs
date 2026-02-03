using System.Text.Json;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

builder.Services.Configure<ProxyOptions>(builder.Configuration.GetSection(ProxyOptions.SectionName));

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
