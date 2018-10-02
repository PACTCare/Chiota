namespace Chiota.Messenger.Usecase
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Extensions;

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
      var publicKeyTrytes = publicKey.ToBytes().EncodeBytesAsString();
      var payload = new TryteString(publicKeyTrytes + Constants.LineBreak + requestAddress.Value + Constants.End);

      var signature = await Task.Run(() => this.SignatureGenerator.Generate(addressPrivateKey, new Hash(requestAddress.Value)));
      foreach (var fragment in signature)
      {
        payload = payload.Concat(fragment);
      }

      return payload;
    }
  }
}