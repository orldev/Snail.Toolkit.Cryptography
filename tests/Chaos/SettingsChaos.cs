using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Extensions;

namespace Snail.Toolkit.Cryptography.Tests.Chaos;

/// <summary>
/// The settings are judged in one place, the options builder. A cipher built by hand, which the README allows,
/// never meets that place.
/// </summary>
public class SettingsChaos
{
    /// <summary>
    /// A key length AES cannot take passes the constructor: PBKDF2 happily derives 20 bytes. The failure comes
    /// later, as a CryptographicException from the first Encrypt on each thread, where it reads as tampering.
    /// </summary>
    [Fact]
    public void SymmetricCipher_BuiltByHandWithAKeyLengthAesCannotTake_RefusesInTheConstructor()
    {
        var settings = Settings();
        settings.DesiredKeyLength = 20;

        Assert.ThrowsAny<ArgumentException>(() => new SymmetricCipher(Options.Create(settings)));
    }

    /// <summary>
    /// One PBKDF2 round is a key derived in a microsecond, which is what the 100 000 minimum exists to refuse.
    /// The constructor accepts it without a word.
    /// </summary>
    [Fact]
    public void SymmetricCipher_BuiltByHandWithOneIteration_Refuses()
    {
        var settings = Settings();
        settings.Iterations = 1;

        Assert.ThrowsAny<ArgumentException>(() => new SymmetricCipher(Options.Create(settings)));
    }

    /// <summary>
    /// The one argument the constructor takes is read without a check, so a null arrives as a
    /// NullReferenceException from inside the cipher instead of an ArgumentNullException naming the parameter.
    /// </summary>
    [Fact]
    public void SymmetricCipher_WithoutOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new SymmetricCipher(null!));
    }

    /// <summary>
    /// The validation messages are compile-time constants naming the default section. A host bound from
    /// "Encryption" is told that 'Cryptography:Passphrase' has to be set, and goes looking in the wrong place.
    /// </summary>
    [Fact]
    public void AddSymmetricCipher_FromACustomSectionMissingThePassphrase_NamesThatSectionInTheFailure()
    {
        var settings = new Dictionary<string, string?> { ["Encryption:Salt"] = "0123456789abcede" };
        var provider = new ServiceCollection()
            .AddSymmetricCipher(Ciphers.Configuration(settings), "Encryption")
            .BuildServiceProvider();

        var error = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<CipherOptions>>().Value);

        Assert.Contains("Encryption:", string.Join(' ', error.Failures), StringComparison.Ordinal);
    }

    private static CipherOptions Settings()
    {
        var settings = new CipherOptions();
        Ciphers.Defaults(settings);

        return settings;
    }
}
