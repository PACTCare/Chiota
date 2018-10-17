namespace Chiota.Messenger.Tests.Service
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;

  internal class SignatureGeneratorStub : ISignatureFragmentGenerator
  {
    /// <inheritdoc />
    public List<Fragment> Generate(AbstractPrivateKey privateKey, Hash hash)
    {
      return new List<Fragment> { new Fragment("STUBFRAGMENTSIGNATURE") };
    }

    /// <inheritdoc />
    public async Task<List<Fragment>> GenerateAsync(AbstractPrivateKey privateKey, Hash hash)
    {
      return new List<Fragment> { new Fragment("STUBFRAGMENTSIGNATURE") };
    }
  }
}