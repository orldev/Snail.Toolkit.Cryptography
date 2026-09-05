global using Xunit;
global using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Extensions;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddSymmetricCipher_FromConfiguration_ResolvesTheCipher()
    {
        var provider = new ServiceCollection()
            .AddSymmetricCipher(Helper.Configuration())
            .BuildServiceProvider();

        Assert.NotNull(provider.GetService<ISymmetricCipher>());
    }

    [Fact]
    public void AddSymmetricCipher_FromConfiguration_BindsEverySetting()
    {
        var options = Options(Helper.Configuration());

        Assert.Equal("0123456789", options.Passphrase);
        Assert.Equal("0123456789abcede", options.Salt);
        Assert.Equal(100_000, options.Iterations);
        Assert.Equal(32, options.DesiredKeyLength);
        Assert.Equal(HashAlgo.SHA512, options.HashMethod);
    }

    /// <summary>
    /// The section name used to be hard-coded, so settings living anywhere else bound nothing at all.
    /// </summary>
    [Fact]
    public void AddSymmetricCipher_FromACustomSection_BindsIt()
    {
        var settings = Helper.Settings.ToDictionary(
            entry => entry.Key.Replace(Helper.Section, "Custom", StringComparison.Ordinal),
            entry => entry.Value);

        var options = Options(Helper.Configuration(settings), "Custom");

        Assert.Equal("0123456789", options.Passphrase);
    }

    [Fact]
    public void AddSymmetricCipher_WithoutAPassphrase_FailsValidation()
    {
        AssertRejected(options => options.Salt = "0123456789abcede", nameof(CipherOptions.Passphrase));
    }

    [Fact]
    public void AddSymmetricCipher_WithoutASalt_FailsValidation()
    {
        AssertRejected(options => options.Passphrase = "secret", nameof(CipherOptions.Salt));
    }

    [Fact]
    public void AddSymmetricCipher_WithAKeyLengthAesCannotTake_FailsValidation()
    {
        AssertRejected(
            options =>
            {
                Helper.Defaults(options);
                options.DesiredKeyLength = 20;
            },
            nameof(CipherOptions.DesiredKeyLength));
    }

    [Fact]
    public void AddSymmetricCipher_WithTooFewIterations_FailsValidation()
    {
        AssertRejected(
            options =>
            {
                Helper.Defaults(options);
                options.Iterations = 1000;
            },
            nameof(CipherOptions.Iterations));
    }

    [Fact]
    public void AddSymmetricCipher_WithAnUndefinedHash_FailsValidation()
    {
        AssertRejected(
            options =>
            {
                Helper.Defaults(options);
                options.HashMethod = (HashAlgo)999;
            },
            nameof(CipherOptions.HashMethod));
    }

    [Fact]
    public void AddSymmetricCipher_WithoutAConfiguration_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => new ServiceCollection().AddSymmetricCipher((IConfiguration)null!));
    }

    [Fact]
    public void AddSymmetricCipher_WithAnEmptySectionName_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => new ServiceCollection().AddSymmetricCipher(Helper.Configuration(), " "));
    }

    private static CipherOptions Options(IConfiguration configuration, string? sectionName = null) =>
        new ServiceCollection()
            .AddSymmetricCipher(configuration, sectionName ?? CipherOptions.SectionName)
            .BuildServiceProvider()
            .GetRequiredService<IOptions<CipherOptions>>()
            .Value;

    private static void AssertRejected(Action<CipherOptions> configure, string setting)
    {
        var provider = new ServiceCollection().AddSymmetricCipher(configure).BuildServiceProvider();

        var error = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<CipherOptions>>().Value);

        Assert.Contains(setting, string.Join(' ', error.Failures), StringComparison.Ordinal);
    }
}
