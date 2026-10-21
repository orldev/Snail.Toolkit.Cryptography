using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Extensions;
using Snail.Toolkit.Cryptography.Interfaces;

const string text = "A secret sealed under Native AOT";

var configuration = new ConfigurationBuilder()
    .AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Cryptography:Passphrase"] = "0123456789",
        ["Cryptography:Salt"] = "0123456789abcede",
        ["Cryptography:Iterations"] = "100000",
        ["Cryptography:DesiredKeyLength"] = "16",
        ["Cryptography:HashMethod"] = "SHA256"
    })
    .Build();

using var provider = new ServiceCollection()
    .AddSymmetricCipher(configuration)
    .BuildServiceProvider();

var settings = provider.GetRequiredService<IOptions<CipherOptions>>().Value;
var cipher = provider.GetRequiredService<ISymmetricCipher>();
var opened = cipher.DecryptFromBase64(cipher.EncryptToBase64(text));

var isBound = settings is { Iterations: 100_000, DesiredKeyLength: 16, HashMethod: HashAlgo.SHA256 };
var isRoundTrip = opened == text;

Console.WriteLine($"bound {isBound}, round trip {isRoundTrip}");

return isBound && isRoundTrip ? 0 : 1;
