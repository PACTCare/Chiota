namespace Chiota.Services
{
  using System;
  using System.Diagnostics;
  using System.IO;

  using Chiota.Models;

  using Org.BouncyCastle.Crypto;
  using Org.BouncyCastle.Crypto.Engines;
  using Org.BouncyCastle.Crypto.Generators;
  using Org.BouncyCastle.Crypto.Modes;
  using Org.BouncyCastle.Crypto.Parameters;
  using Org.BouncyCastle.Math;
  using Org.BouncyCastle.Security;

  // https://stackoverflow.com/questions/33813108/bouncycastle-diffie-hellman
  // To be replaced by https://en.wikipedia.org/wiki/Supersingular_isogeny_key_exchange
  // https://github.com/Microsoft/PQCrypto-SIDH
  
  public class DiffieHellman 
  {
    private const string Algorithm = "ECDH";

    private const int KeyBitSize = 256;

    private const int NonceBitSize = 128;

    private const int MacBitSize = 128;

    private const int DefaultPrimeProbability = 30;

    public DiffieHellmanObject CreateAlice()
    {
      var aliceKeyGen = GeneratorUtilities.GetKeyPairGenerator(Algorithm);
      var aliceGenerator = new DHParametersGenerator();
      aliceGenerator.Init(KeyBitSize, DefaultPrimeProbability, new SecureRandom());
      var aliceParameters = aliceGenerator.GenerateParameters();

      aliceKeyGen.Init(new DHKeyGenerationParameters(new SecureRandom(), aliceParameters));

      var aliceKeyPair = aliceKeyGen.GenerateKeyPair();

      return new DiffieHellmanObject
                            {
                              PublicKey = aliceKeyPair.Public,
                              PrimInteger = aliceParameters.P,
                              NaturalInteger = aliceParameters.G,
                              PrivateKey = aliceKeyPair.Private
                            };
    }

    public DiffieHellmanObject CreateBob(DiffieHellmanObject alice)
    {
      var bobKeyGen = GeneratorUtilities.GetKeyPairGenerator(Algorithm);
      var bobParameters = new DHParameters(alice.PrimInteger, alice.NaturalInteger);

      bobKeyGen.Init(new DHKeyGenerationParameters(new SecureRandom(), bobParameters));

      var bobKeyPair = bobKeyGen.GenerateKeyPair();
      return new DiffieHellmanObject
               {
                 PublicKey = bobKeyPair.Public,
                 PrimInteger = bobParameters.P,
                 NaturalInteger = bobParameters.G,
                 PrivateKey = bobKeyPair.Private
               };
    }


    public static void TestMethod()
    {
      //BEGIN SETUP ALICE
      var aliceKeyGen = GeneratorUtilities.GetKeyPairGenerator(Algorithm);
      var aliceGenerator = new DHParametersGenerator();
      aliceGenerator.Init(KeyBitSize, DefaultPrimeProbability, new SecureRandom());
      DHParameters aliceParameters = aliceGenerator.GenerateParameters();

      var aliceKGP = new DHKeyGenerationParameters(new SecureRandom(), aliceParameters);
      aliceKeyGen.Init(aliceKGP);

      AsymmetricCipherKeyPair aliceKeyPair = aliceKeyGen.GenerateKeyPair();
      var aliceKeyAgree = AgreementUtilities.GetBasicAgreement(Algorithm);
      aliceKeyAgree.Init(aliceKeyPair.Private);
      //END SETUP ALICE

      /////AT THIS POINT, Alice's Public Key, Alice's Parameter P and Alice's Parameter G are sent unsecure to BOB

      //BEGIN SETUP BOB
      var bobKeyGen = GeneratorUtilities.GetKeyPairGenerator(Algorithm);
      DHParameters bobParameters = new DHParameters(aliceParameters.P, aliceParameters.G);

      KeyGenerationParameters bobKGP = new DHKeyGenerationParameters(new SecureRandom(), bobParameters);
      bobKeyGen.Init(bobKGP);

      AsymmetricCipherKeyPair bobKeyPair = bobKeyGen.GenerateKeyPair();
      IBasicAgreement bobKeyAgree = AgreementUtilities.GetBasicAgreement(Algorithm);
      bobKeyAgree.Init(bobKeyPair.Private);
      //END SETUP BOB

      BigInteger aliceAgree = aliceKeyAgree.CalculateAgreement(bobKeyPair.Public);
      BigInteger bobAgree = bobKeyAgree.CalculateAgreement(aliceKeyPair.Public);

      if (!aliceAgree.Equals(bobAgree))
      {
        throw new Exception("Keys do not match.");
      }

      byte[] nonSecretMessage = GetBytes("HeaderMessageForASDF");
      byte[] secretMessage = GetBytes("Secret message contents");
      byte[] decNonSecretBytes;

      KeyParameter sharedKey = new KeyParameter(aliceAgree.ToByteArrayUnsigned());

      var encMessage = EncryptMessage(sharedKey, nonSecretMessage, secretMessage);
      var decMessage = DecryptMessage(sharedKey, encMessage, out decNonSecretBytes);

      var decNonSecretMessage = GetString(decNonSecretBytes);
      var decSecretMessage = GetString(decMessage);

      Debug.WriteLine(decNonSecretMessage + " - " + decSecretMessage);

      return;
    }

    public static byte[] EncryptMessage(string sharedKey, string nonSecretMessage, string secretMessage)
    {
      return EncryptMessage(new KeyParameter(Convert.FromBase64String(sharedKey)), GetBytes(nonSecretMessage), GetBytes(secretMessage));
    }

    public static byte[] EncryptMessage(KeyParameter sharedKey, byte[] nonSecretMessage, byte[] secretMessage)
    {
      if (nonSecretMessage != null && nonSecretMessage.Length > 255) throw new Exception("Non Secret Message Too Long!");
      byte nonSecretLength = nonSecretMessage == null ? (byte)0 : (byte)nonSecretMessage.Length;

      var nonce = new byte[NonceBitSize / 8];
      var rand = new SecureRandom();
      rand.NextBytes(nonce, 0, nonce.Length);

      var cipher = new GcmBlockCipher(new AesFastEngine());
      var aeadParameters = new AeadParameters(sharedKey, MacBitSize, nonce, nonSecretMessage);
      cipher.Init(true, aeadParameters);

      //Generate Cipher Text With Auth Tag
      var cipherText = new byte[cipher.GetOutputSize(secretMessage.Length)];
      var len = cipher.ProcessBytes(secretMessage, 0, secretMessage.Length, cipherText, 0);
      cipher.DoFinal(cipherText, len);

      using (var combinedStream = new MemoryStream())
      {
        using (var binaryWriter = new BinaryWriter(combinedStream))
        {
          //Prepend Authenticated Payload
          binaryWriter.Write(nonSecretLength);
          binaryWriter.Write(nonSecretMessage);

          //Prepend Nonce
          binaryWriter.Write(nonce);
          //Write Cipher Text
          binaryWriter.Write(cipherText);
        }
        return combinedStream.ToArray();
      }
    }

    public static string DecryptMessage(string sharedKey, byte[] encryptedMessage, out string nonSecretPayload)
    {
      byte[] nonSecretPayloadBytes;
      byte[] payload = DecryptMessage(new KeyParameter(Convert.FromBase64String(sharedKey)), encryptedMessage, out nonSecretPayloadBytes);

      nonSecretPayload = GetString(nonSecretPayloadBytes);
      return GetString(payload);
    }

    public static byte[] DecryptMessage(KeyParameter sharedKey, byte[] encryptedMessage, out byte[] nonSecretPayloadBytes)
    {
      using (var cipherStream = new MemoryStream(encryptedMessage))
      using (var cipherReader = new BinaryReader(cipherStream))
      {
        //Grab Payload
        int nonSecretLength = (int)cipherReader.ReadByte();
        nonSecretPayloadBytes = cipherReader.ReadBytes(nonSecretLength);

        //Grab Nonce
        var nonce = cipherReader.ReadBytes(NonceBitSize / 8);

        var cipher = new GcmBlockCipher(new AesFastEngine());
        var parameters = new AeadParameters(sharedKey, MacBitSize, nonce, nonSecretPayloadBytes);
        cipher.Init(false, parameters);

        //Decrypt Cipher Text
        var cipherText = cipherReader.ReadBytes(encryptedMessage.Length - nonSecretLength - nonce.Length);
        var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

        try
        {
          var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
          cipher.DoFinal(plainText, len);
        }
        catch (InvalidCipherTextException)
        {
          //Return null if it doesn't authenticate
          return null;
        }

        return plainText;
      }
    }

    static byte[] GetBytes(string str)
    {
      if (str == null) return null;
      return System.Text.Encoding.Unicode.GetBytes(str);
    }

    static string GetString(byte[] bytes)
    {
      if (bytes == null) return null;
      return System.Text.Encoding.Unicode.GetString(bytes, 0, bytes.Length);
    }
  }

}
