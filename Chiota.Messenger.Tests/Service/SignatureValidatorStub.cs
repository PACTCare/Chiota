namespace Chiota.Messenger.Tests.Service
{
  using System.Collections.Generic;

  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;

  internal class SignatureValidatorStub : ISignatureValidator
  {
    public SignatureValidatorStub(bool result = true)
    {
      this.Result = result;
    }

    private bool Result { get; }

    /// <inheritdoc />
    public bool ValidateFragments(List<Fragment> fragments, Hash hash, TryteString publicKey)
    {
      return this.Result;
    }
  }
}