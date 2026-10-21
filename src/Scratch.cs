using System.Buffers;
using System.Security.Cryptography;

namespace Snail.Toolkit.Cryptography;

/// <summary>
/// Bytes for the length of one call: the caller's stack buffer when they fit, the shared pool beyond.
/// </summary>
/// <remarks>
/// <para>
/// Measured on the Base64 paths of <see cref="SymmetricCipher"/>: with scratch memory a 32-byte text costs 192 B to
/// seal and 88 B to open, which is the result string and the Base64 text; two arrays per call cost 144 B more, and
/// 2.1 KB more for a kilobyte of text.
/// </para>
/// <para>
/// A secret scratch is wiped before it is given back, so a plaintext never stays in a pooled array the next caller
/// rents. An envelope is public and is only returned.
/// </para>
/// </remarks>
internal readonly ref struct Scratch
{
    private readonly byte[]? _rented;
    private readonly bool _isSecret;

    private Scratch(int length, Span<byte> stack, bool isSecret)
    {
        _rented = length > stack.Length ? ArrayPool<byte>.Shared.Rent(length) : null;
        _isSecret = isSecret;
        Bytes = (_rented ?? stack)[..length];
    }

    /// <summary>The bytes, exactly as many as were asked for.</summary>
    public Span<byte> Bytes { get; }

    /// <summary>Scratch for a plaintext: wiped when disposed.</summary>
    public static Scratch Secret(int length, Span<byte> stack) => new(length, stack, isSecret: true);

    /// <summary>Scratch for an envelope: public, so only given back when disposed.</summary>
    public static Scratch Public(int length, Span<byte> stack) => new(length, stack, isSecret: false);

    /// <summary>Wipes a secret and returns a pooled array.</summary>
    public void Dispose()
    {
        if (_isSecret)
            CryptographicOperations.ZeroMemory(Bytes);

        if (_rented is not null)
            ArrayPool<byte>.Shared.Return(_rented);
    }
}
