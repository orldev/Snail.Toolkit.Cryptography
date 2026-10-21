using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography.Extensions;

/// <summary>
/// Registers <see cref="ISymmetricCipher"/> and the settings it runs on.
/// </summary>
public static class ServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        /// <summary>Registers the cipher, binding its settings from a configuration section.</summary>
        /// <remarks>
        /// The section name is a parameter rather than a constant read off <paramref name="configuration"/>.
        /// The previous overload hard-coded <c>GetSection("Cryptography")</c> while documenting its
        /// parameter as the section itself, so passing an already-scoped section bound nothing and left
        /// every setting at its default.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="configuration"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="sectionName"/> is empty.</exception>
        public IServiceCollection AddSymmetricCipher(
            IConfiguration configuration,
            string sectionName = CipherOptions.SectionName)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

            CipherRules.Apply(services.AddOptions<CipherOptions>().Bind(configuration.GetSection(sectionName)), sectionName);
            services.TryAddSingleton<ISymmetricCipher, SymmetricCipher>();

            return services;
        }

        /// <summary>Registers the cipher with settings supplied in code.</summary>
        /// <remarks>
        /// There is no parameterless overload any more. The one that existed configured the passphrase
        /// "123456", and because options configuration is additive it silently overwrote a passphrase
        /// already bound from configuration whenever anything called it a second time.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="configure"/> is null.</exception>
        public IServiceCollection AddSymmetricCipher(Action<CipherOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configure);

            CipherRules.Apply(services.AddOptions<CipherOptions>().Configure(configure), section: null);
            services.TryAddSingleton<ISymmetricCipher, SymmetricCipher>();

            return services;
        }
    }
}
