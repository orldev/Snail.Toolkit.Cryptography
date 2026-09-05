global using Xunit;
global using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Extensions;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography.Tests;

public class ServiceCollectionExtensionsTests
{
    private readonly IServiceCollection _services = new ServiceCollection()
        .AddSymmetricCipher(Helper.GetConfiguration());

    [Fact]
    public void AddToServices_ReturnContains()
    {
        Assert.Contains(_services, d => d.ServiceType == typeof(ISymmetricCipher));
        Assert.Contains(_services, d => d.ServiceType == typeof(IConfigureOptions<SymCryptoOpts>));
    }
    

    [Fact]
    public void Match_OptionsWithAppSettings_ReturnEqual()
    {
        using var serviceProvider = _services.BuildServiceProvider();
        
        var options = serviceProvider.GetService<IOptions<SymCryptoOpts>>()?.Value;
        Assert.NotNull(options);
        
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.Passphrase)}"], options.Passphrase);
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.IV)}"], options.IV);
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.Salt)}"], options.Salt);
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.Iterations)}"], options.Iterations.ToString());
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.DesiredKeyLength)}"], options.DesiredKeyLength.ToString());
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.HashMethod)}"], options.HashMethod.ToString());
    }
    
    [Fact]
    public void GetFromServices_ReturnNotNull()
    {
        using var serviceProvider = _services.BuildServiceProvider();
        
        var cryptography = serviceProvider.GetService<ISymmetricCipher>();
        Assert.NotNull(cryptography);
    }
}