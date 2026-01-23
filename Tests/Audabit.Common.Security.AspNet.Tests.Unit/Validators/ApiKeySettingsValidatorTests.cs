using Audabit.Common.Security.AspNet.Settings;
using Audabit.Common.Security.AspNet.Tests.Unit.TestHelpers;
using Audabit.Common.Security.AspNet.Validators;

namespace Audabit.Common.Security.AspNet.Tests.Unit.Validators;

public class ApiKeySettingsValidatorTests
{
    public class ApiKeySettingsValidatorTestsBase
    {
        protected readonly Fixture _fixture;
        protected readonly ApiKeySettingsValidator _validator;

        public ApiKeySettingsValidatorTestsBase()
        {
            _fixture = FixtureFactory.Create();
            _fixture.Customize<ApiKeySettings>(c => c
                .With(x => x.HeaderName, "X-Api-Key")
                .With(x => x.Key, "default-api-key-with-at-least-32-characters-long"));
            _validator = new ApiKeySettingsValidator();
        }
    }

    public class Validate : ApiKeySettingsValidatorTestsBase
    {
        [Fact]
        public void GivenValidSettings_ShouldPass()
        {
            // Arrange
            var settings = _fixture.Create<ApiKeySettings>();

            // Act
            var result = _validator.Validate(settings);

            // Assert
            result.IsValid.ShouldBeTrue();
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("short-key")]
        public void GivenInvalidKey_ShouldFail(string? invalidKey)
        {
            // Arrange
            var settings = _fixture.Build<ApiKeySettings>()
                .With(x => x.Key, invalidKey!)
                .Create();

            // Act
            var result = _validator.Validate(settings);

            // Assert
            result.IsValid.ShouldBeFalse();
            result.Errors.ShouldContain(e => e.PropertyName == nameof(ApiKeySettings.Key));
        }

        [Theory]
        [InlineData("X-Api-Key")]
        [InlineData("X-Custom-Header")]
        [InlineData("x-api-key")]
        [InlineData("Authorization")]
        [InlineData("AUTHORIZATION")]
        [InlineData("authorization")]
        public void GivenValidHeaderName_ShouldPass(string validHeaderName)
        {
            // Arrange
            var settings = _fixture.Build<ApiKeySettings>()
                .With(x => x.HeaderName, validHeaderName)
                .Create();

            // Act
            var result = _validator.Validate(settings);

            // Assert
            result.IsValid.ShouldBeTrue();
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("Api-Key")]
        [InlineData("Custom-Header")]
        [InlineData("Bearer")]
        [InlineData("ApiKey")]
        [InlineData("Y-Custom")]
        public void GivenInvalidHeaderName_ShouldFail(string? invalidHeaderName)
        {
            // Arrange
            var settings = _fixture.Build<ApiKeySettings>()
                .With(x => x.HeaderName, invalidHeaderName!)
                .Create();

            // Act
            var result = _validator.Validate(settings);

            // Assert
            result.IsValid.ShouldBeFalse();
            result.Errors.ShouldContain(e => e.PropertyName == nameof(ApiKeySettings.HeaderName));
        }
    }
}