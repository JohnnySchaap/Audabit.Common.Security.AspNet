# Audabit.Common.Security.AspNet

An API key authentication middleware library for ASP.NET Core Web APIs with attribute-based bypass support.

## Why You Should Use API Key Authentication

Exposing APIs without authentication is a security risk, but implementing authentication manually in every controller action is error-prone and leads to inconsistent security.

### Simple, Effective Protection

API key authentication provides a simple layer of security for service-to-service communication and internal APIs. It's not meant for user authentication (use OAuth2/JWT for that), but for scenarios where you need to control which clients can access your API.

This package can be used in combination with OAuth2/JWT authentication. If you want your endpoints protected with an API key by default (recommended) and only allow specific endpoints to use OAuth authentication instead, simply add the `[NotApiKeyProtected]` attribute to those endpoints. This creates a layered security approach where API key protection is the default, and you explicitly opt-in to alternative authentication schemes where needed.

### Prevent Accidental Exposure

Without authentication middleware, it's easy to forget to secure a new endpoint. This library applies authentication by default to all endpoints, requiring you to explicitly opt-out with `[NotApiKeyProtected]`. This "secure by default" approach prevents accidentally exposing sensitive endpoints.

### Configuration-Based Security

API keys are managed in configuration, not hardcoded in source control. The library validates your security configuration at startup using FluentValidation, catching configuration errors before deployment rather than discovering them in production.

## Dependencies

This library depends on the following Audabit packages:
- **Audabit.Common.Validation.AspNet** - Used for validating security settings (e.g., API keys configuration)

## Features

- **API Key Authentication**: Header-based API key validation for all endpoints
- **Configurable Header Name**: Customize the API key header name (defaults to `X-API-Key`)
- **Attribute-Based Bypass**: Use `[NotApiKeyProtected]` attribute to bypass authentication
- **Path-Based Bypass**: Automatic bypass for `/health` endpoint
- **Environment-Based Bypass**: Disable in development for easier local testing
- **Settings Validation**: FluentValidation ensures API key configuration is valid at startup
- **Timing Attack Prevention**: Uses constant-time comparison for API key validation to prevent timing side-channel attacks
- **ConfigureAwait Best Practices**: All async operations use `ConfigureAwait(false)` for improved performance and compatibility
- **.NET 10.0 Support**: Built for the latest .NET framework

> **Note on ConfigureAwait(false)**: This library follows Microsoft's recommended async/await best practices by using `ConfigureAwait(false)` on all await statements. This eliminates unnecessary context switches and improves performance by allowing continuations to run on any thread pool thread rather than marshaling back to the original synchronization context. While primarily beneficial for performance, this also prevents potential deadlocks in legacy applications.

## Installation

### Via .NET CLI

```bash
dotnet add package Audabit.Common.Security.AspNet
```

### Via Package Manager Console

```powershell
Install-Package Audabit.Common.Security.AspNet
```

## Getting Started

### Configuration

Add API key settings to `appsettings.json`:

```json
{
  "ApiKeySettings": {
    "Key": "your-secret-api-key-here-at-least-32-characters",
    "HeaderName": "X-Api-Key"
  }
}
```

### Basic Usage

Register and configure API key middleware in `Program.cs`:

```csharp
using Audabit.Common.Security.AspNet.Extensions;
using Audabit.Common.Security.AspNet.Settings;

var builder = WebApplication.CreateBuilder(args);

// Register API key settings with validation
var apiKeySettingsSection = builder.Configuration.GetSection(nameof(ApiKeySettings));
builder.Services.AddApiKeySecurity(apiKeySettingsSection);

var app = builder.Build();

// Add API key middleware (bypassed in development)
app.UseApiKeyMiddleware(app.Environment.IsDevelopment());

app.MapControllers();
app.Run();
```

### Bypass Authentication

Use `[NotApiKeyProtected]` attribute to bypass authentication:

```csharp
[ApiController]
[Route("[controller]")]
[NotApiKeyProtected]  // Bypass API key for this entire controller
public class HomeController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new { status = "Public endpoint" });
    }
}
```

### Client Usage

Include the API key in request headers:

```http
GET /api/weatherforecast HTTP/1.1
Host: localhost:5000
X-Api-Key: your-secret-api-key-here-at-least-32-characters
```

## How It Works

The `UseApiKeyMiddleware` middleware:

1. Checks if endpoint has `[NotApiKeyProtected]` attribute  bypass
2. Checks if request path is `/health`  bypass
3. Verifies API key is configured in settings → return 500 if not
4. Extracts API key from request header
5. Compares with configured API key value
6. Returns 403 Forbidden if key is missing or invalid
7. Proceeds to next middleware if key is valid

## Middleware Order

```csharp
app.UseExceptionMiddleware();
app.UseCorrelationIdMiddleware();
// ... other middleware
app.UseApiKeyMiddleware(app.Environment.IsDevelopment());  // After routing, before controllers
app.MapControllers();
```

## Related Packages

This library works seamlessly with other Audabit packages:

- **[Audabit.Common.ServiceInfo.AspNet](https://dev.azure.com/johnnyschaap/Audabit/_artifacts/feed/Audabit/NuGet/Audabit.Common.ServiceInfo.AspNet)**: Provides NotApiKeyProtected attribute functionality used by this security middleware
- **[Audabit.Common.Validation.AspNet](https://dev.azure.com/johnnyschaap/Audabit/_artifacts/feed/Audabit/NuGet/Audabit.Common.Validation.AspNet)**: Uses FluentValidation for API key settings validation (dependency)

While this package depends on Audabit.Common.Validation.AspNet, combining it with ServiceInfo provides a complete security solution.

## Build and Test

### Prerequisites

- .NET 10.0 SDK or later
- Visual Studio 2022 / VS Code / Rider (optional)

### Building

```bash
dotnet restore
dotnet build
```

### Running Tests

```bash
dotnet test
```

### Creating NuGet Package

```bash
dotnet pack --configuration Release
```

## CI/CD Pipeline

This project uses Azure DevOps pipelines with the following features:

- **Automatic Versioning**: Major and minor versions from csproj, patch version from build number
- **Prerelease Builds**: Non-main branches create prerelease packages (e.g., `9.0.123-feature-auth`)
- **Code Formatting**: Enforces `dotnet format` standards
- **Code Coverage**: Generates and publishes code coverage reports
- **Automated Publishing**: Pushes packages to Azure Artifacts feed

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Guidelines

1. Follow existing code style and conventions
2. Ensure all tests pass before submitting PR
3. Add tests for new features
4. Update documentation as needed
5. Run `dotnet format` before committing

## License

Copyright © Audabit Software Solutions B.V. 2026

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) file for details.

## Authors

- [John Schaap](https://github.com/JohnnySchaap) - [Audabit Software Solutions B.V.](https://audabit.nl)

## Acknowledgments

- Designed for [ASP.NET Core](https://dotnet.microsoft.com/apps/aspnet)
