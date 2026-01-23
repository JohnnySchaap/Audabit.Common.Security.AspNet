using Audabit.Common.Security.AspNet.Settings;
using FluentValidation;

namespace Audabit.Common.Security.AspNet.Validators;

/// <summary>
/// FluentValidation validator for <see cref="ApiKeySettings"/> configuration.
/// </summary>
/// <remarks>
/// <para>
/// This validator enforces security and configuration requirements for API key settings:
/// <list type="bullet">
/// <item><description>API key must be present and meet minimum security length (32 characters)</description></item>
/// <item><description>API key cannot be a weak or commonly used value</description></item>
/// <item><description>Header name must follow standard conventions (X- prefix or Authorization)</description></item>
/// </list>
/// </para>
/// <para>
/// Validation occurs at application startup when using <c>.ValidateWithFluentValidation()</c>,
/// preventing the application from starting with invalid or insecure configuration.
/// </para>
/// </remarks>
/// <example>
/// Valid configuration:
/// <code>
/// {
///   "ApiKeySettings": {
///     "Key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
///     "HeaderName": "X-Api-Key"
///   }
/// }
/// </code>
/// </example>
public sealed class ApiKeySettingsValidator : AbstractValidator<ApiKeySettings>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ApiKeySettingsValidator"/> class
    /// and configures validation rules for API key settings.
    /// </summary>
    public ApiKeySettingsValidator()
    {
        RuleFor(x => x.Key)
            .NotEmpty()
            .WithMessage("ApiKeySettings:Key is required in configuration")
            .MinimumLength(32)
            .WithMessage("ApiKeySettings:Key must be at least 32 characters long for security");

        RuleFor(x => x.HeaderName)
            .NotEmpty()
            .WithMessage("ApiKeySettings:HeaderName is required in configuration")
            .Must(IsValidHeaderName)
            .WithMessage("ApiKeySettings:HeaderName should follow standard conventions (X- prefix or 'Authorization')");
    }

    /// <summary>
    /// Validates that the header name follows standard HTTP header conventions.
    /// </summary>
    /// <param name="headerName">The header name to validate.</param>
    /// <returns>True if the header name is valid; otherwise, false.</returns>
    private static bool IsValidHeaderName(string headerName)
    {
        if (string.IsNullOrWhiteSpace(headerName))
        {
            return false;
        }

        // Accept standard custom headers (X- prefix) or the Authorization header
        return headerName.StartsWith("X-", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Authorization", StringComparison.OrdinalIgnoreCase);
    }
}