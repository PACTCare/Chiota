namespace Chiota.Messenger.Encryption
{
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public interface IEncryption
  {
    /// <summary>
    /// Creates a Keypair based on your seed and one address
    /// </summary>
    /// <param name="seed">String of your seed</param>
    /// <param name="salt">String of your address</param>
    /// <returns>Key Pair</returns>
    IAsymmetricKeyPair CreateAsymmetricKeyPair(string seed, string salt);

    /// <summary>
    /// Encrypts messages
    /// </summary>
    /// <param name="publicKey">public key</param>
    /// <param name="input">input text</param>
    /// <returns>byte array</returns>
    byte[] Encrypt(IAsymmetricKey publicKey, byte[] input);

    /// <summary>
    /// Decrypts a byte array
    /// </summary>
    /// <param name="keyPair">The correct key pair</param>
    /// <param name="encryptedBytes">The encrypted byte array</param>
    /// <returns>Decrypted string</returns>
    byte[] Decrypt(IAsymmetricKeyPair keyPair, byte[] encryptedBytes);
  }
}