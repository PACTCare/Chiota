namespace Chiota.Messenger.Entity
{
  using Chiota.Messenger.Extensions;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Curl;
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class PublicKeyPayload : TryteString
  {
    private Hash hash;

    public PublicKeyPayload(IAsymmetricKey publicKey, TryteString requestAddress)
      : base(publicKey.ToBytes().EncodeBytesAsString() + Constants.LineBreak + requestAddress.Value + Constants.End)
    {
      this.PublicKey = publicKey;
      this.RequestAddress = requestAddress;
    }

    public PublicKeyPayload(string trytes)
      : base(trytes)
    {
    }

    public Hash Hash
    {
      get
      {
        if (this.hash != null)
        {
          return this.hash;
        }

        if (this.Curl == null)
        {
          this.Curl = new Curl(CurlMode.CurlP81);
        }

        this.Curl.Absorb(this.ToTrits());

        var hashTrits = new int[Tangle.Net.Utils.Constants.TritHashLength];
        this.Curl.Squeeze(hashTrits);

        this.hash = new Hash(Converter.TritsToTrytes(hashTrits));

        return this.hash;
      }
    }

    private AbstractCurl Curl { get; set; }

    private IAsymmetricKey PublicKey { get; }

    private TryteString RequestAddress { get; }
  }
}