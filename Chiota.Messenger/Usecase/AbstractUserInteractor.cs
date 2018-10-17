namespace Chiota.Messenger.Usecase
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public abstract class AbstractUserInteractor<TIn, T> : IUsecaseInteractor<TIn, T>
    where T : BaseResponse
  {
    protected AbstractUserInteractor(ISignatureFragmentGenerator signatureGenerator)
    {
      this.SignatureGenerator = signatureGenerator;
    }

    private ISignatureFragmentGenerator SignatureGenerator { get; }

    public abstract Task<T> ExecuteAsync(TIn request);

    protected async Task<TryteString> CreateSignedPublicKeyPayloadAsync(IAsymmetricKey publicKey, TryteString requestAddress, AbstractPrivateKey addressPrivateKey)
    {
      var payload = new PublicKeyPayload(publicKey, requestAddress);
      var signature = await this.SignatureGenerator.GenerateAsync(addressPrivateKey, payload.Hash);

      var signedPayload = (TryteString)payload;
      foreach (var fragment in signature)
      {
        signedPayload = signedPayload.Concat(fragment);
      }

      return signedPayload;
    }
  }
}