namespace Chiota.Messenger.Service
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class NtruKeyExchange
  {
    private readonly int maxEncryptionSize;

    private readonly int maxSize;

    private readonly NTRUParameters ntruParameters; 

    public NtruKeyExchange(NTRUParamSets.NTRUParamNames ntruParams)
    {
      switch (ntruParams)
      {
        case NTRUParamSets.NTRUParamNames.A2011743:
          this.ntruParameters = NTRUParamSets.APR2011743FAST;
          this.maxSize = 105;
          this.maxEncryptionSize = 1022;
          break;
        case NTRUParamSets.NTRUParamNames.E1499EP1:
          this.ntruParameters = NTRUParamSets.EES1499EP1FAST;
          this.maxSize = 247;
          this.maxEncryptionSize = 2062;
          break;
        default:
          throw new Exception("Unsupported NTRU Param set");
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
    /// Encrypts messages with NTRU
    /// </summary>
    /// <param name="publicKey">public key</param>
    /// <param name="input">input text</param>
    /// <returns>byte array</returns>
    public byte[] Encrypt(IAsymmetricKey publicKey, byte[] input)
    {
      var bytes = new List<byte[]>();
      using (var cipher = new NTRUEncrypt(this.ntruParameters))
      {
        foreach (var byt in ArraySplit(input, this.maxSize))
        {
          cipher.Initialize(publicKey);
          bytes.Add(cipher.Encrypt(byt));
        }
      }

      return bytes.SelectMany(a => a).ToArray();
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

    private static IEnumerable<byte[]> ArraySplit(byte[] bytes, int bufferLength)
    {
      byte[] result;

      var i = 0;
      for (; bytes.Length > (i + 1) * bufferLength; i++)
      {
        result = new byte[bufferLength];
        Array.Copy(bytes, i * bufferLength, result, 0, bufferLength);
        yield return result;
      }

      var bufferLeft = bytes.Length - (i * bufferLength);
      if (bufferLeft > 0)
      {
        result = new byte[bufferLeft];
        Array.Copy(bytes, i * bufferLength, result, 0, bufferLeft);
        yield return result;
      }
    }
  }
}
