namespace Audabit.Common.Security.AspNet.Settings;

/// <summary>
/// Configuration settings for API key authentication.
/// </summary>
/// <remarks>
/// <para>
/// This record is used to configure API key-based authentication for ASP.NET Core applications.
/// It is typically bound from configuration (appsettings.json) and validated at startup using FluentValidation.
/// </para>
/// <para>
/// The API key should be stored securely and never committed to source control.
/// Use environment variables, Azure Key Vault, or other secure configuration providers for production environments.
/// </para>
/// </remarks>
/// <example>
/// Configuration in appsettings.json:
/// <code>
/// {
///   "ApiKeySettings": {
///     "Key": "your-secure-api-key-here",
///     "HeaderName": "X-Api-Key"
///   }
/// }
/// </code>
/// 
/// Or using environment variables:
/// <code>
/// ApiKeySettings__Key=your-secure-api-key-here
/// ApiKeySettings__HeaderName=X-Api-Key
/// </code>
/// </example>
public sealed record ApiKeySettings
{
    /// <summary>
    /// Gets or initializes the API key value used for authentication.
    /// </summary>
    /// <value>
    /// The secret API key that clients must provide in the request header.
    /// This value is validated using FluentValidation to ensure it meets security requirements.
    /// </value>
    /// <remarks>
    /// This should be a strong, randomly generated string. Never use default or weak values in production.
    /// Store this value securely using environment variables or a secrets manager.
    /// </remarks>
    public string Key { get; init; } = string.Empty;

    /// <summary>
    /// Gets or initializes the HTTP header name where the API key should be provided.
    /// </summary>
    /// <value>
    /// The name of the HTTP header that will contain the API key. Default is "X-Api-Key".
    /// </value>
    /// <remarks>
    /// <para>
    /// The header name must follow standard conventions: either start with "X-" prefix (case-insensitive)
    /// or be exactly "Authorization" (case-insensitive). This is validated by <see cref="Validators.ApiKeySettingsValidator"/>.
    /// </para>
    /// <para>
    /// Common valid values include "X-Api-Key", "X-Custom-Header", or "Authorization".
    /// HTTP header names are case-insensitive per RFC 7230, but this property value itself is case-sensitive in configuration.
    /// </para>
    /// </remarks>
    public string HeaderName { get; init; } = "X-Api-Key";
}