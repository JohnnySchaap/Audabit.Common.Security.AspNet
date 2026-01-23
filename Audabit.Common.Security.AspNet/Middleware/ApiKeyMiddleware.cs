using System.Security.Cryptography;
using System.Text;
using Audabit.Common.Security.AspNet.Attributes;
using Audabit.Common.Security.AspNet.Settings;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Audabit.Common.Security.AspNet.Middleware;

/// <summary>
/// Middleware that enforces API key authentication for HTTP requests.
/// </summary>
/// <remarks>
/// <para>
/// This middleware validates that incoming requests contain a valid API key in the request header.
/// Endpoints can be excluded from authentication by applying the <see cref="NotApiKeyProtectedAttribute"/>.
/// </para>
/// <para>
/// The middleware performs validation in the following order:
/// <list type="number">
/// <item><description>Checks if the endpoint has <see cref="NotApiKeyProtectedAttribute"/> (bypass if present)</description></item>
/// <item><description>Checks if the path is /health or /swagger (bypass for health checks and API documentation)</description></item>
/// <item><description>Validates API key configuration is present</description></item>
/// <item><description>Validates the request header contains a matching API key</description></item>
/// </list>
/// </para>
/// <para>
/// <b>Bypassed Paths:</b>
/// <list type="bullet">
/// <item><description>/health* - Health check endpoints</description></item>
/// <item><description>/swagger* - Swagger API documentation</description></item>
/// </list>
/// </para>
/// <para>
/// Returns 403 Forbidden if the API key is missing or invalid.
/// Returns 500 Internal Server Error if the API key is not properly configured.
/// </para>
/// </remarks>
public class ApiKeyMiddleware(RequestDelegate next, IOptions<ApiKeySettings> apiKeySettings)
{
    /// <summary>
    /// Processes the HTTP request and validates the API key.
    /// </summary>
    /// <param name="context">The HTTP context for the current request.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Check for bypass attribute
        if (context.GetEndpoint()?.Metadata.GetMetadata<NotApiKeyProtectedAttribute>() != null)
        {
            await next(context).ConfigureAwait(false);
            return;
        }

        // Health check bypass
        // Swagger bypass (for API documentation)
        if (context.Request.Path.StartsWithSegments("/health") ||
            context.Request.Path.StartsWithSegments("/swagger"))
        {
            await next(context).ConfigureAwait(false);
            return;
        }

        // Validate configuration
        var apiKey = apiKeySettings.Value.Key;
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsync("Service configuration error.").ConfigureAwait(false);
            return;
        }

        // Validate API key using constant-time comparison to prevent timing attacks
        var headerName = apiKeySettings.Value.HeaderName;
        if (!context.Request.Headers.TryGetValue(headerName, out var extractedApiKey) ||
            !ConstantTimeEquals(extractedApiKey!, apiKey))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Forbidden.").ConfigureAwait(false);
            return;
        }

        await next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Performs constant-time string comparison to prevent timing attacks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why Constant-Time Comparison?</b>
    /// </para>
    /// <para>
    /// Standard string comparison (==, string.Equals) stops immediately when it finds a character mismatch.
    /// This creates measurable timing differences:
    /// <list type="bullet">
    /// <item><description>"a000000" vs "xyz789" → Fast (fails at position 0)</description></item>
    /// <item><description>"xyz0000" vs "xyz789" → Slower (fails at position 3)</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Attackers can exploit these microsecond timing differences over thousands of requests to brute-force
    /// the API key character by character. Instead of 62^20 attempts for a 20-character key, they only need ~1,240 attempts.
    /// </para>
    /// <para>
    /// <b>Solution:</b> <see cref="CryptographicOperations.FixedTimeEquals"/> always compares ALL bytes
    /// regardless of where mismatches occur, eliminating timing side-channels. This is a critical security
    /// requirement for authentication systems.
    /// </para>
    /// </remarks>
    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;

        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);

        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }
}