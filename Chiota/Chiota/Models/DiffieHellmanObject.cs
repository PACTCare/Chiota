namespace Chiota.Models
{
  using Org.BouncyCastle.Crypto;
  using Org.BouncyCastle.Math;

  public class DiffieHellmanObject
  {
    // To be shared
    public AsymmetricKeyParameter PublicKey { get; set; }

    public BigInteger PrimInteger { get; set; }

    public BigInteger NaturalInteger { get; set; }

    // To be stored
    public AsymmetricKeyParameter PrivateKey { get; set; }
  }
}
