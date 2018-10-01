namespace Chiota.Messenger.Usecase.CreateUser
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Extensions;
  using Chiota.Messenger.Service;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;

  public class CreateUserInteractor : AbstractUserInteractor<CreateUserRequest, CreateUserResponse>
  {
    public CreateUserInteractor(
      IMessenger messenger,
      IAddressGenerator addressGenerator,
      IEncryption encryption,
      ISignatureFragmentGenerator signatureGenerator)
      : base(signatureGenerator)
    {
      this.Messenger = messenger;
      this.AddressGenerator = addressGenerator;
      this.Encryption = encryption;
    }

    private IMessenger Messenger { get; }

    private IAddressGenerator AddressGenerator { get; }

    private IEncryption Encryption { get; }

    /// <inheritdoc />
    public override async Task<CreateUserResponse> ExecuteAsync(CreateUserRequest request)
    {
      try
      {
        var publicKeyAddress = this.AddressGenerator.GetAddress(request.Seed, Constants.MessengerSecurityLevel, 0);
        var requestAddress = publicKeyAddress.DeriveRequestAddress();

        var ntruKeyPair = this.Encryption.CreateAsymmetricKeyPair(request.Seed.Value.ToLower(), publicKeyAddress.Value);
        var payload = this.CreateSignedPublicKeyPayload(ntruKeyPair.PublicKey, requestAddress, publicKeyAddress.PrivateKey);

        await this.Messenger.SendMessageAsync(new Message(payload, publicKeyAddress));
        return new CreateUserResponse
                 {
                   Code = ResponseCode.Success,
                   NtruKeyPair = ntruKeyPair,
                   PublicKeyAddress = publicKeyAddress,
                   RequestAddress = requestAddress
                 };
      }
      catch (MessengerException exception)
      {
        return new CreateUserResponse { Code = exception.Code };
      }
      catch (Exception)
      {
        return new CreateUserResponse { Code = ResponseCode.UnkownException };
      }
    }
  }
}