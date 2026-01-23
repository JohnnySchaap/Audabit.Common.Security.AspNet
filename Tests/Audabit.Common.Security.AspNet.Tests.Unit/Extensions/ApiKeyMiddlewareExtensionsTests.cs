using Audabit.Common.Security.AspNet.Extensions;
using Audabit.Common.Security.AspNet.Settings;
using Audabit.Common.Security.AspNet.Tests.Unit.TestHelpers;
using Audabit.Common.Security.AspNet.Validators;
using FluentValidation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Audabit.Common.Security.AspNet.Tests.Unit.Extensions;

public class ApiKeyMiddlewareExtensionsTests
{
    public class ApiKeyMiddlewareExtensionsTestsBase
    {
        protected readonly Fixture _fixture;
        protected readonly IApplicationBuilder _app;

        public ApiKeyMiddlewareExtensionsTestsBase()
        {
            _fixture = FixtureFactory.Create();
            _app = Substitute.For<IApplicationBuilder>();
        }
    }

    public class AddApiKeySecurity : ApiKeyMiddlewareExtensionsTestsBase
    {
        private readonly IServiceCollection _services;
        private readonly IConfigurationSection _configurationSection;

        public AddApiKeySecurity()
        {
            _services = new ServiceCollection();
            _services.AddScoped<IValidator<ApiKeySettings>, ApiKeySettingsValidator>();

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ApiKeySettings:Key", "test-api-key-with-at-least-32-characters-long" },
                    { "ApiKeySettings:HeaderName", "X-Api-Key" }
                })
                .Build();

            _configurationSection = configuration.GetSection("ApiKeySettings");
        }

        [Fact]
        public void GivenValidServicesAndConfiguration_ShouldReturnServices()
        {
            // Act
            var result = _services.AddApiKeySecurity(_configurationSection);

            // Assert
            result.ShouldBe(_services);
        }

        [Fact]
        public void GivenNullServices_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Should.Throw<ArgumentNullException>(() =>
                ((IServiceCollection)null!).AddApiKeySecurity(_configurationSection));
        }

        [Fact]
        public void GivenNullConfiguration_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Should.Throw<ArgumentNullException>(() =>
                _services.AddApiKeySecurity(null!));
        }

        [Fact]
        public void GivenValidServicesAndConfiguration_ShouldRegisterAndBindApiKeySettings()
        {
            // Act
            _services.AddApiKeySecurity(_configurationSection);

            // Assert
            var serviceProvider = _services.BuildServiceProvider();
            var settings = serviceProvider.GetRequiredService<IOptions<ApiKeySettings>>();
            settings.ShouldNotBeNull();
            settings.Value.Key.ShouldBe("test-api-key-with-at-least-32-characters-long");
            settings.Value.HeaderName.ShouldBe("X-Api-Key");
        }

        [Theory]
        [InlineData("", "X-Api-Key")]
        [InlineData("short-key", "X-Api-Key")]
        [InlineData("   ", "X-Api-Key")]
        [InlineData("test-api-key-with-at-least-32-characters-long", "")]
        public void GivenInvalidConfiguration_ShouldThrowOptionsValidationException(
            string key,
            string headerName)
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddScoped<IValidator<ApiKeySettings>, ApiKeySettingsValidator>();

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ApiKeySettings:Key", key },
                    { "ApiKeySettings:HeaderName", headerName }
                })
                .Build();
            var configSection = configuration.GetSection("ApiKeySettings");

            services.AddApiKeySecurity(configSection);
            var serviceProvider = services.BuildServiceProvider();

            // Act & Assert
            Should.Throw<OptionsValidationException>(() =>
            {
                var settings = serviceProvider.GetService<IOptions<ApiKeySettings>>();
                _ = settings!.Value; // Access Value to trigger validation
            });
        }
    }

    public class UseApiKeyMiddleware : ApiKeyMiddlewareExtensionsTestsBase
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void GivenValidApplicationBuilder_ShouldReturnBuilder(bool isDevelopment)
        {
            // Arrange
            _app.Use(Arg.Any<Func<RequestDelegate, RequestDelegate>>()).Returns(_app);

            // Act
            var result = _app.UseApiKeyMiddleware(isDevelopment);

            // Assert
            result.ShouldBe(_app);
        }

        [Fact]
        public void GivenNullApplicationBuilder_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Should.Throw<ArgumentNullException>(() =>
                ((IApplicationBuilder)null!).UseApiKeyMiddleware(false));
        }

        [Fact]
        public void GivenValidApplicationBuilder_ShouldRegisterMiddleware()
        {
            // Act
            _app.UseApiKeyMiddleware(false);

            // Assert
            _app.Received(1).Use(Arg.Any<Func<RequestDelegate, RequestDelegate>>());
        }

        [Fact]
        public void GivenValidApplicationBuilderWithRequireApiKeyTrue_ShouldNotRegisterMiddleware()
        {
            // Act
            _app.UseApiKeyMiddleware(true);

            // Assert
            _app.DidNotReceive().Use(Arg.Any<Func<RequestDelegate, RequestDelegate>>());
        }

    }
}