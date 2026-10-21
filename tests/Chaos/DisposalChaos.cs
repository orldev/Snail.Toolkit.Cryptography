using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;

namespace Snail.Toolkit.Cryptography.Tests.Chaos;

/// <summary>
/// What the cipher keeps after the threads that used it are gone, and what its <c>Dispose</c> really wipes.
/// </summary>
public class DisposalChaos
{
    /// <summary>
    /// The README and the Dispose remarks promise that disposing the cipher wipes the key. The AES-GCM instances
    /// wipe their copies; the derived key the cipher itself holds in <c>_key</c> stays in managed memory, readable
    /// from any heap dump until the garbage collector happens to overwrite it.
    /// </summary>
    [Fact]
    public void Dispose_AfterUse_WipesTheDerivedKey()
    {
        var cipher = new SymmetricCipher(Options.Create(Settings()));
        var key = Field<byte[]>(cipher, "_key");
        cipher.Encrypt([1, 2, 3]);

        cipher.Dispose();

        Assert.True(key.AsSpan().IndexOfAnyExcept((byte)0) < 0, $"The derived key is still in memory after Dispose: {Convert.ToHexString(key)}");
    }

    /// <summary>
    /// A singleton cipher in a service whose thread pool grows and shrinks for months used to keep one AES-GCM
    /// instance, with its native key handle, for every thread that ever encrypted. What stays behind after a
    /// thousand threads must be bounded by the pool, not by the threads seen.
    /// </summary>
    [Fact]
    public void Encrypt_FromAThousandShortLivedThreads_KeepsNoInstanceOfAnEndedThread()
    {
        using var cipher = new SymmetricCipher(Options.Create(Settings()));
        RunToCompletion(1000, () => cipher.Encrypt([1, 2, 3]));
        var idle = Field<AesGcm?[]>(cipher, "_idle");

        int kept = idle.Count(instance => instance is not null);

        Assert.True(kept <= 16, $"{kept} AES-GCM instances are kept idle after a thousand threads ended; the pool holds at most 16.");
    }

    /// <summary>
    /// A call after Dispose is refused, and the exception has to name the cipher, not a type inside it;
    /// otherwise a stack trace in a log sends the reader to the wrong type.
    /// </summary>
    [Fact]
    public void Encrypt_AfterDispose_NamesTheCipherInTheException()
    {
        var cipher = new SymmetricCipher(Options.Create(Settings()));
        cipher.Dispose();

        var error = Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt([1, 2, 3]));

        Assert.Equal(typeof(SymmetricCipher).FullName, error.ObjectName);
    }

    /// <summary>
    /// Disposing while other threads are mid-operation is a caller's mistake, but the only exception it may produce
    /// is ObjectDisposedException: never a CryptographicException that looks like tampering, never a crash.
    /// </summary>
    [Fact]
    public void Dispose_WhileEightThreadsEncrypt_OnlyEverThrowsObjectDisposed()
    {
        var cipher = new SymmetricCipher(Options.Create(Settings()));
        var unexpected = new ConcurrentBag<Exception>();
        using var start = new ManualResetEventSlim();
        var workers = new Thread[8];

        for (int index = 0; index < workers.Length; index++)
        {
            workers[index] = new Thread(() => RoundTripUntilDisposed(cipher, start, unexpected));
            workers[index].Start();
        }

        start.Set();
        Thread.Sleep(20);
        cipher.Dispose();

        foreach (var worker in workers)
            worker.Join();

        Assert.Empty(unexpected);
    }

    private static void RoundTripUntilDisposed(SymmetricCipher cipher, ManualResetEventSlim start, ConcurrentBag<Exception> unexpected)
    {
        start.Wait();

        try
        {
            for (int round = 0; round < 1_000_000; round++)
                cipher.DecryptFromBase64(cipher.EncryptToBase64("a message"));
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception error)
        {
            unexpected.Add(error);
        }
    }

    private static void RunToCompletion(int threads, Action work)
    {
        var started = new Thread[threads];

        for (int index = 0; index < threads; index++)
        {
            started[index] = new Thread(() => work());
            started[index].Start();
        }

        foreach (var thread in started)
            thread.Join();
    }

    private static T Field<T>(object target, string name)
    {
        var field = target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);

        return (T)field!.GetValue(target)!;
    }

    private static CipherOptions Settings()
    {
        var settings = new CipherOptions();
        Ciphers.Defaults(settings);

        return settings;
    }
}
