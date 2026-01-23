namespace Audabit.Common.Security.AspNet.Attributes;

/// <summary>
/// Marks an endpoint or controller to bypass API key authentication.
/// </summary>
/// <remarks>
/// <para>
/// Apply this attribute to controllers or action methods that should be accessible without API key authentication.
/// This is typically used for health check endpoints, documentation endpoints, or public information endpoints.
/// </para>
/// <para>
/// This attribute is checked by the API key middleware to determine whether to enforce authentication.
/// When present, the middleware will skip API key validation for the decorated controller or action.
/// </para>
/// <para>
/// Use this attribute sparingly and only for endpoints that genuinely need to be publicly accessible,
/// as it bypasses a security layer.
/// </para>
/// </remarks>
/// <example>
/// Apply to a controller to bypass authentication for all actions:
/// <code>
/// [NotApiKeyProtected]
/// public class HomeController : ControllerBase
/// {
///     // All actions in this controller bypass API key authentication
/// }
/// </code>
/// 
/// Or apply to a specific action method:
/// <code>
/// public class StatusController : ControllerBase
/// {
///     [NotApiKeyProtected]
///     public IActionResult HealthCheck()
///     {
///         return Ok("Healthy");
///     }
/// }
/// </code>
/// </example>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class NotApiKeyProtectedAttribute : Attribute;