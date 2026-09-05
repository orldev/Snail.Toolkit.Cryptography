namespace Snail.Toolkit.Cryptography.Entities;

/// <summary>
/// The hash a passphrase is stretched through when the encryption key is derived.
/// </summary>
/// <remarks>
/// SHA-1 was removed rather than deprecated: it is the only choice here that weakens the derived key,
/// and leaving it selectable meant a configuration file could quietly pick it.
/// </remarks>
public enum HashAlgo
{
    /// <summary>SHA-2 with a 256-bit output.</summary>
    SHA256 = 256,

    /// <summary>SHA-2 with a 384-bit output.</summary>
    SHA384 = 384,

    /// <summary>SHA-2 with a 512-bit output.</summary>
    SHA512 = 512
}
