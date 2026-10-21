using System.Text;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;

namespace Snail.Toolkit.Cryptography.Benchmarks;

/// <summary>
/// Measures the per-call cost of sealing and opening an envelope, the path every encrypted value takes.
/// </summary>
/// <remarks>
/// Key derivation is paid once, in <see cref="Setup"/>, as the cipher pays it once in its constructor; what is
/// left is the AES-GCM work itself and, on the Base64 paths, the scratch and the result. Read the Allocated
/// column: the time of a few microseconds moves with the machine, the bytes do not.
/// </remarks>
[MemoryDiagnoser]
public class Envelopes
{
    private SymmetricCipher _cipher = null!;
    private byte[] _plainBytes = [];
    private byte[] _sealedBytes = [];
    private string _plainText = string.Empty;
    private string _sealedText = string.Empty;

    /// <summary>Length of the plaintext in bytes: a short secret and a kilobyte document.</summary>
    [Params(32, 1024)]
    public int Length { get; set; }

    /// <summary>Derives the key once, seals the inputs the opening benchmarks read and checks that both paths round-trip.</summary>
    [GlobalSetup]
    public void Setup()
    {
        var settings = new CipherOptions
        {
            Passphrase = "0123456789",
            Salt = "0123456789abcede",
            Iterations = 100_000
        };

        _cipher = new SymmetricCipher(Options.Create(settings));
        _plainText = new string('x', Length);
        _plainBytes = Encoding.UTF8.GetBytes(_plainText);
        _sealedBytes = _cipher.Encrypt(_plainBytes);
        _sealedText = _cipher.EncryptToBase64(_plainText);

        if (!_cipher.Decrypt(_sealedBytes).AsSpan().SequenceEqual(_plainBytes))
            throw new InvalidOperationException("The bytes did not round-trip.");

        if (_cipher.DecryptFromBase64(_sealedText) != _plainText || _cipher.DecryptFromBase64(Convert.ToBase64String(_sealedBytes)) != _plainText)
            throw new InvalidOperationException("The Base64 text did not round-trip, or the two paths seal different envelopes.");
    }

    /// <summary>Disposes the cipher and the AES-GCM instance it kept for each thread.</summary>
    [GlobalCleanup]
    public void Cleanup() => _cipher.Dispose();

    /// <summary>Seals bytes into an envelope.</summary>
    [Benchmark]
    public byte[] Encrypt() => _cipher.Encrypt(_plainBytes);

    /// <summary>Opens an envelope into bytes.</summary>
    [Benchmark]
    public byte[] Decrypt() => _cipher.Decrypt(_sealedBytes);

    /// <summary>Seals text into a Base64 envelope.</summary>
    [Benchmark]
    public string EncryptToBase64() => _cipher.EncryptToBase64(_plainText);

    /// <summary>Opens a Base64 envelope into text.</summary>
    [Benchmark]
    public string DecryptFromBase64() => _cipher.DecryptFromBase64(_sealedText);
}
