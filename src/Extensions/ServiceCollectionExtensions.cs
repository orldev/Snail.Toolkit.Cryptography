using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography.Extensions;

/// <summary>
/// Provides extension methods for <see cref="IServiceCollection"/> to configure symmetric encryption services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds symmetric encryption services to the dependency injection container with optional configuration.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="options">Optional action to configure <see cref="SymCryptoOpts"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="services"/> is null.</exception>
    /// <remarks>
    /// <para>
    /// When no options are provided, default values will be used:
    /// - Passphrase: "123456" (INSECURE - for development only)
    /// - IV: "abcede0123456789" (INSECURE - for development only)
    /// </para>
    /// <para>
    /// SECURITY WARNING: The default values provide no real security and should NEVER be used in production.
    /// Always provide proper configuration in production environments.
    /// </para>
    /// <example>
    /// Secure configuration example:
    /// <code>
    /// services.AddSymmetricCipher(opts => {
    ///     opts.Passphrase = Configuration["Crypto:Key"];
    ///     opts.IV = Configuration["Crypto:IV"];
    ///     opts.Iterations = 600_000;
    ///     opts.HashMethod = HashAlgo.SHA512;
    ///     opts.DesiredKeyLength = 32;
    /// });
    /// </code>
    /// </example>
    /// </remarks>
    public static IServiceCollection AddSymmetricCipher(
        this IServiceCollection services, 
        Action<SymCryptoOpts>? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Configure(options ??= o =>
        {
            o.Passphrase = "123456";
            o.IV = "abcede0123456789";
        });
        services.TryAddSingleton<ISymmetricCipher, SymmetricCipher>();
        return services;
    }
    
    /// <summary>
    /// Adds symmetric encryption services to the dependency injection container using configuration.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="configuration">The <see cref="IConfiguration"/> section containing crypto settings.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="services"/> or <paramref name="configuration"/> is null.</exception>
    /// <remarks>
    /// <para>
    /// Expects configuration section with these fields (example appsettings.json):
    /// <code>
    /// "Cryptography": {
    ///     "Passphrase": "secure-passphrase-here",
    ///     "IV": "base64-encoded-iv-here",
    ///     "Salt": "base64-encoded-salt-here",
    ///     "Iterations": 600000,
    ///     "DesiredKeyLength": 32,
    ///     "HashMethod": "SHA512"
    /// }
    /// </code>
    /// </para>
    /// <para>
    /// SECURITY NOTES:
    /// - Passphrase should come from secure secret storage, not plain config files
    /// - IV and Salt should be cryptographically random values
    /// - Iterations should be ≥ 100,000 for security-sensitive applications
    /// </para>
    /// </remarks>
    public static IServiceCollection AddSymmetricCipher(
        this IServiceCollection services, 
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Configure<SymCryptoOpts>(configuration.GetSection("Cryptography"));
        services.TryAddSingleton<ISymmetricCipher, SymmetricCipher>();
        return services;
    }
}