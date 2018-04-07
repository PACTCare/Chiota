namespace Chiota.Services
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;

  using Tangle.Net.Utils;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class NtruKex
  {
    private const int MaxTextSize = 106; 

    private const int EncryptedTextSize = 1022;

    private readonly NTRUParameters encParams = NTRUParamSets.APR2011743FAST; // N743, q2048 , EES743EP1 

    public IAsymmetricKeyPair CreateAsymmetricKeyPair()
    {
      var keyGen = new NTRUKeyGenerator(this.encParams);
      var keyPair = keyGen.GenerateKeyPair();

      // publicKey sometimes has only 1025 bytes instead of 1026 after conversation?!
      while (keyPair.PublicKey.ToBytes().ToTrytes().ToBytes().Length != 1026)
      {
        keyPair = keyGen.GenerateKeyPair();
      }

      return keyPair;
    }

    /// <summary>
    /// Encrypts messages with NTRU
    /// </summary>
    /// <param name="publicKey">public key</param>
    /// <param name="input">input text</param>
    /// <returns>byte array</returns>
    public byte[] Encrypt(IAsymmetricKey publicKey, string input)
    {
      var bytes = new List<byte[]>();
      using (var cipher = new NTRUEncrypt(this.encParams))
      {
        var splitText = this.SplitByLength(input, MaxTextSize - 1);
        foreach (var text in splitText)
        {
          cipher.Initialize(publicKey);
          var data = Encoding.UTF8.GetBytes(text);
          bytes.Add(cipher.Encrypt(data));
        }
      }

      return bytes.SelectMany(a => a).ToArray();
    }

    public string Decrypt(IAsymmetricKeyPair privateKey, byte[] encryptedText)
    {
      var splitArray = encryptedText.Select((x, i) => new { Key = i / EncryptedTextSize, Value = x })
        .GroupBy(x => x.Key, x => x.Value, (k, g) => g.ToArray())
        .ToArray();
      var decryptedText = "";
      foreach (var bytes in splitArray)
      {
        using (var cipher = new NTRUEncrypt(this.encParams))
        {
          cipher.Initialize(privateKey);
          var dec = cipher.Decrypt(bytes);
          decryptedText += Encoding.UTF8.GetString(dec);
        }
      }

      return decryptedText;
    }

    private IEnumerable<string> SplitByLength(string str, int maxLength)
    {
      var index = 0;
      while (true)
      {
        if (index + maxLength >= str.Length)
        {
          yield return str.Substring(index);
          yield break;
        }

        yield return str.Substring(index, maxLength);
        index += maxLength;
      }
    }
  }
}
