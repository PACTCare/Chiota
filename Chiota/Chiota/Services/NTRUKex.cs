namespace Chiota.Services
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class NtruKex
  {
    private readonly int maxEncryptionSize;

    private readonly int maxSize;

    private readonly NTRUParameters ntruParameters; 

    public NtruKex(bool keyExchangeParameters = false)
    {
      if (keyExchangeParameters)
      {
        // For initial key exchange!
        this.ntruParameters = NTRUParamSets.APR2011743FAST;
        this.maxSize = 105;
        this.maxEncryptionSize = 1022;
      }
      else
      {
        // 38 times faster, but results in to messages instead of one
        this.ntruParameters = NTRUParamSets.EES1499EP1FAST;
        this.maxSize = 247;
        this.maxEncryptionSize = 2062;
      }
    }

    /// <summary>
    /// Creates a NTRU Keypair based on your seed and one address
    /// </summary>
    /// <param name="seed">String of your seed</param>
    /// <param name="saltAddress">String of your address</param>
    /// <returns>Key Pair</returns>
    public IAsymmetricKeyPair CreateAsymmetricKeyPair(string seed, string saltAddress)
    {
      var passphrase = Encoding.UTF8.GetBytes(seed);
      var salt = Encoding.UTF8.GetBytes(saltAddress);

      var keyGen = new NTRUKeyGenerator(this.ntruParameters, false);

      var keys = keyGen.GenerateKeyPair(passphrase, salt);

      return keys;
    }

    /// <summary>
    /// Decrypts a byte array
    /// </summary>
    /// <param name="keyPair">The correct key pair</param>
    /// <param name="encryptedBytes">The encrypted byte array</param>
    /// <returns>Decrypted string</returns>
    public byte[] Decrypt(IAsymmetricKeyPair keyPair, byte[] encryptedBytes)
    {
      var splitArray = encryptedBytes.Select((x, i) => new { Key = i / this.maxEncryptionSize, Value = x })
        .GroupBy(x => x.Key, x => x.Value, (k, g) => g.ToArray())
        .ToArray();
      var bytesList = new List<byte[]>();

      foreach (var bytes in splitArray)
      {
        using (var cipher = new NTRUEncrypt(this.ntruParameters))
        {
          try
          {
            cipher.Initialize(keyPair);
            bytesList.Add(cipher.Decrypt(bytes));
          }
          catch
          {
            // ignored
          }
        }
      }

      return bytesList.SelectMany(a => a).ToArray();
    }
  }
}
