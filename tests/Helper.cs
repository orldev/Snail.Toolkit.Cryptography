using Microsoft.Extensions.Configuration;

namespace Snail.Toolkit.Cryptography.Tests;

public static class Helper
{
    public static string Client = "Cryptography";
    
    public static readonly Dictionary<string, string> InMemorySettings = new () {
        {$"{Client}:Passphrase", "0123456789"},
        {$"{Client}:IV", "abcede0123456789"},
        {$"{Client}:Salt", "0123456789abcede"},
        {$"{Client}:Iterations", "1000"},
        {$"{Client}:DesiredKeyLength", "16"},
        {$"{Client}:HashMethod", "SHA512"}
    };

    public static IConfiguration GetConfiguration()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(InMemorySettings!)
            .Build();

        return configuration;
    }
}