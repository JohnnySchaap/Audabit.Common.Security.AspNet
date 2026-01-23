using Audabit.Common.Security.AspNet.Middleware;
using Audabit.Common.Security.AspNet.Settings;
using Audabit.Common.Validation.AspNet.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Audabit.Common.Security.AspNet.Extensions;

/// <summary>
/// Provides extension methods for registering API key security services and middleware in ASP.NET Core applications.
/// </summary>
public static class ApiKeyMiddlewareExtensions
{
    /// <summary>
    /// Registers API key settings with configuration binding and startup validation.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="configuration">The configuration section containing API key settings.</param>
    /// <returns>The <see cref="IServiceCollection"/> for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> or <paramref name="configuration"/> is null.</exception>
    /// <remarks>
    /// <para>
    /// This method configures API key settings with FluentValidation startup validation to ensure
    /// the API key is properly configured before the application starts.
    /// </para>
    /// <para>
    /// The configuration section should contain a "Key" property with the actual API key value (minimum 32 characters)
    /// and a "HeaderName" property specifying which HTTP header should contain the API key.
    /// Validation will fail if the API key is missing, empty, or does not meet security requirements.
    /// </para>
    /// </remarks>
    /// <example>
    /// Register API key settings in Program.cs:
    /// <code>
    /// var apiKeySection = builder.Configuration.GetSection(nameof(ApiKeySettings));
    /// builder.Services.AddApiKeySecurity(apiKeySection);
    /// </code>
    /// 
    /// Corresponding appsettings.json:
    /// <code>
    /// {
    ///   "ApiKeySettings": {
    ///     "Key": "your-secure-api-key-with-at-least-32-characters",
    ///     "HeaderName": "X-Api-Key"
    ///   }
    /// }
    /// </code>
    /// </example>
    public static IServiceCollection AddApiKeySecurity(
        this IServiceCollection services,
        IConfigurationSection configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services
            .AddOptions<ApiKeySettings>()
            .Bind(configuration)
            .ValidateWithFluentValidation();

        return services;
    }

    /// <summary>
    /// Adds API key authentication middleware to the application pipeline.
    /// </summary>
    /// <param name="builder">The <see cref="IApplicationBuilder"/> to configure.</param>
    /// <param name="isDevelopment">Whether the application is running in development mode.</param>
    /// <returns>The <see cref="IApplicationBuilder"/> for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    /// <remarks>
    /// <para>
    /// In development mode (<paramref name="isDevelopment"/> is true), this middleware is bypassed
    /// to simplify local development and testing. In all other environments, the middleware enforces
    /// API key authentication for all endpoints unless marked with <c>[NotApiKeyProtected]</c>.
    /// </para>
    /// <para>
    /// The middleware expects the API key to be provided in the request header as configured in
    /// <see cref="ApiKeySettings"/>. If the key is missing or invalid, a 403 Forbidden response is returned.
    /// </para>
    /// <para>
    /// This middleware should be added early in the pipeline, typically after exception handling
    /// but before routing and endpoint execution.
    /// </para>
    /// </remarks>
    /// <example>
    /// Configure middleware in Program.cs:
    /// <code>
    /// app.UseApiKeyMiddleware(app.Environment.IsDevelopment());
    /// </code>
    /// 
    /// Or explicitly control environments:
    /// <code>
    /// var isDev = builder.Environment.IsDevelopment();
    /// app.UseApiKeyMiddleware(isDev);
    /// </code>
    /// </example>
    public static IApplicationBuilder UseApiKeyMiddleware(
        this IApplicationBuilder builder,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (isDevelopment)
        {
            return builder;
        }

        return builder.UseMiddleware<ApiKeyMiddleware>();
    }
}