using Microsoft.Extensions.Configuration;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Extensions;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography.Tests;

public static class Ciphers
{
    public const string Section = CipherOptions.SectionName;

    public static readonly Dictionary<string, string?> Settings = new()
    {
        [$"{Section}:{nameof(CipherOptions.Passphrase)}"] = "0123456789",
        [$"{Section}:{nameof(CipherOptions.Salt)}"] = "0123456789abcede",
        [$"{Section}:{nameof(CipherOptions.Iterations)}"] = "100000",
        [$"{Section}:{nameof(CipherOptions.DesiredKeyLength)}"] = "32",
        [$"{Section}:{nameof(CipherOptions.HashMethod)}"] = "SHA512"
    };

    public static IConfiguration Configuration(Dictionary<string, string?>? settings = null) =>
        new ConfigurationBuilder().AddInMemoryCollection(settings ?? Settings).Build();

    public static ISymmetricCipher Cipher(Action<CipherOptions>? configure = null) =>
        new ServiceCollection()
            .AddSymmetricCipher(configure ?? Defaults)
            .BuildServiceProvider()
            .GetRequiredService<ISymmetricCipher>();

    public static void Defaults(CipherOptions options)
    {
        options.Passphrase = "0123456789";
        options.Salt = "0123456789abcede";
        options.Iterations = 100_000;
    }
}
