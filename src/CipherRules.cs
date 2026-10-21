using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;

namespace Snail.Toolkit.Cryptography;

/// <summary>
/// The rules every setting is judged by, whichever way the settings arrived.
/// </summary>
/// <remarks>
/// The registration applies them when the host starts and the constructor applies them to settings handed to it
/// directly, and both name the failing setting the same way, under the section it was read from when there was one.
/// They used to live in the registration alone: a cipher built by hand with a 20-byte key was constructed and failed
/// on its first use with the exception documented for a forged envelope, and a host bound from a section of its own
/// was told that 'Cryptography:Passphrase' had to be set.
/// </remarks>
internal static class CipherRules
{
    private const int MinimumIterations = 100_000;

    private static readonly Rule[] All =
    [
        new(nameof(CipherOptions.Passphrase), "set", settings => !string.IsNullOrWhiteSpace(settings.Passphrase)),
        new(
            nameof(CipherOptions.Salt),
            "set, or the derived key is a pure function of the passphrase and precomputable",
            settings => !string.IsNullOrWhiteSpace(settings.Salt)),
        new(nameof(CipherOptions.Iterations), $"at least {MinimumIterations}", settings => settings.Iterations >= MinimumIterations),
        new(
            nameof(CipherOptions.DesiredKeyLength),
            "16, 24 or 32, the key sizes AES accepts",
            settings => settings.DesiredKeyLength is 16 or 24 or 32),
        new(nameof(CipherOptions.HashMethod), $"a defined {nameof(HashAlgo)} value", settings => Enum.IsDefined(settings.HashMethod))
    ];

    /// <summary>The demands the settings fail, each naming its setting; empty when every rule holds.</summary>
    public static IReadOnlyList<string> Failures(CipherOptions settings, string? section)
    {
        List<string> failures = [];

        foreach (var rule in All)
        {
            if (!rule.Holds(settings))
                failures.Add(rule.Message(section));
        }

        return failures;
    }

    /// <summary>Puts every rule on the builder, to be checked when the host starts.</summary>
    public static void Apply(OptionsBuilder<CipherOptions> builder, string? section)
    {
        foreach (var rule in All)
            builder.Validate(rule.Holds, rule.Message(section));

        builder.ValidateOnStart();
    }

    private sealed record Rule(string Setting, string Demand, Func<CipherOptions, bool> Holds)
    {
        public string Message(string? section) =>
            section is null ? $"'{Setting}' has to be {Demand}." : $"'{section}:{Setting}' has to be {Demand}.";
    }
}
