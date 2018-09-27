namespace Chiota.Messenger.Tests.Encryption
{
  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Tests.Repository;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  internal class EncryptionStub : IEncryption
  {
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
      return input;
    }
  }
}