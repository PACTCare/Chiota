namespace Chiota.Messenger.Tests.Encryption
{
  using System;
  using System.Collections.Generic;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Tests.Repository;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  internal class EncryptionStub : IEncryption
  {
    public EncryptionStub(NTRUParamSets.NTRUParamNames ntruParams = NTRUParamSets.NTRUParamNames.E1499EP1)
    {
      switch (ntruParams)
      {
        case NTRUParamSets.NTRUParamNames.A2011743:
          this.MaxEncryptionSize = 1022;
          break;
        case NTRUParamSets.NTRUParamNames.E1499EP1:
          this.MaxEncryptionSize = 2062;
          break;
        default:
          throw new Exception("Unsupported NTRU Param set");
      }
    }

    private int MaxEncryptionSize { get; }

    /// <inheritdoc />
    public IAsymmetricKeyPair CreateAsymmetricKeyPair(string seed, string salt)
    {
      return InMemoryContactRepository.NtruKeyPair;
    }

    /// <inheritdoc />
    public byte[] Decrypt(IAsymmetricKeyPair keyPair, byte[] encryptedBytes)
    {
      return encryptedBytes;
    }

    /// <inheritdoc />
    public byte[] Encrypt(IAsymmetricKey publicKey, byte[] input)
    {
      var inputList = new List<byte>(input);

      while (inputList.Count < this.MaxEncryptionSize)
      {
        inputList.Add(0);
      }

      return inputList.ToArray();
    }
  }
}