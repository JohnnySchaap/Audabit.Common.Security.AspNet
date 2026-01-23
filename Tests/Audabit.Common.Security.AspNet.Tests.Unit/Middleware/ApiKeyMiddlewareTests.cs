using Audabit.Common.Security.AspNet.Attributes;
using Audabit.Common.Security.AspNet.Middleware;
using Audabit.Common.Security.AspNet.Settings;
using Audabit.Common.Security.AspNet.Tests.Unit.TestHelpers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Audabit.Common.Security.AspNet.Tests.Unit.Middleware;

public class ApiKeyMiddlewareTests
{
    public class ApiKeyMiddlewareTestsBase
    {
        protected readonly Fixture _fixture;
        protected readonly RequestDelegate _next;

        public ApiKeyMiddlewareTestsBase()
        {
            _fixture = FixtureFactory.Create();
            _next = Substitute.For<RequestDelegate>();
        }
    }

    public class InvokeAsync : ApiKeyMiddlewareTestsBase
    {
        [Theory, AutoData]
        public async Task GivenNullContext_ShouldThrowArgumentNullException(string validApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act & Assert
            await Should.ThrowAsync<ArgumentNullException>(() => middleware.InvokeAsync(null!));
        }

        [Theory, AutoData]
        public async Task GivenValidApiKey_ShouldCallNextMiddleware(string validApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var context = new DefaultHttpContext();
            context.Request.Headers["X-API-Key"] = validApiKey;
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            await _next.Received(1).Invoke(context);
            context.Response.StatusCode.ShouldBe(200);
        }

        [Theory, AutoData]
        public async Task GivenNotApiKeyProtectedAttribute_ShouldBypassValidation(string validApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var context = new DefaultHttpContext();
            var endpoint = new Endpoint(
                _ => Task.CompletedTask,
                new EndpointMetadataCollection(new NotApiKeyProtectedAttribute()),
                "test");
            context.SetEndpoint(endpoint);
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            await _next.Received(1).Invoke(context);
            context.Response.StatusCode.ShouldBe(200);
        }

        [Theory, AutoData]
        public async Task GivenHealthCheckPath_ShouldBypassValidation(string validApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var context = new DefaultHttpContext();
            context.Request.Path = "/health";
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            await _next.Received(1).Invoke(context);
            context.Response.StatusCode.ShouldBe(200);
        }

        [Theory, AutoData]
        public async Task GivenHealthCheckSubPath_ShouldBypassValidation(string validApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var context = new DefaultHttpContext();
            context.Request.Path = "/health/readyz";
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            await _next.Received(1).Invoke(context);
            context.Response.StatusCode.ShouldBe(200);
        }

        [Theory, AutoData]
        public async Task GivenSwaggerPath_ShouldBypassValidation(string validApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var context = new DefaultHttpContext();
            context.Request.Path = "/swagger";
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            await _next.Received(1).Invoke(context);
            context.Response.StatusCode.ShouldBe(200);
        }

        [Theory, AutoData]
        public async Task GivenSwaggerSubPath_ShouldBypassValidation(string validApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var context = new DefaultHttpContext();
            context.Request.Path = "/swagger/v1/swagger.json";
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            await _next.Received(1).Invoke(context);
            context.Response.StatusCode.ShouldBe(200);
        }

        [Fact]
        public async Task GivenEmptyApiKeyConfiguration_ShouldReturn500()
        {
            // Arrange
            var emptySettings = Options.Create(new ApiKeySettings { Key = "" });
            var context = new DefaultHttpContext();
            context.Response.Body = new MemoryStream();
            var middleware = new ApiKeyMiddleware(_next, emptySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            context.Response.StatusCode.ShouldBe(500);
            await _next.DidNotReceive().Invoke(context);
        }

        [Theory, AutoData]
        public async Task GivenMissingApiKey_ShouldReturn403(string validApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var context = new DefaultHttpContext();
            context.Response.Body = new MemoryStream();
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            context.Response.StatusCode.ShouldBe(403);
            await _next.DidNotReceive().Invoke(context);
        }

        [Theory, AutoData]
        public async Task GivenInvalidApiKey_ShouldReturn403(string validApiKey, string invalidApiKey)
        {
            // Arrange
            var apiKeySettings = Options.Create(new ApiKeySettings { Key = validApiKey });
            var context = new DefaultHttpContext();
            context.Response.Body = new MemoryStream();
            context.Request.Headers["X-API-Key"] = invalidApiKey;
            var middleware = new ApiKeyMiddleware(_next, apiKeySettings);

            // Act
            await middleware.InvokeAsync(context);

            // Assert
            context.Response.StatusCode.ShouldBe(403);
            await _next.DidNotReceive().Invoke(context);
        }
    }
}