namespace Chiota.Messenger.Usecase.CreateUser
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;

  public class CreateUserInteractor : IUsecaseInteractor<CreateUserRequest, CreateUserResponse>
  {
    public CreateUserInteractor(IMessenger messenger, IAddressGenerator addressGenerator, IEncryption encryption)
    {
      this.Messenger = messenger;
      this.AddressGenerator = addressGenerator;
      this.Encryption = encryption;
    }

    private IMessenger Messenger { get; }

    private IAddressGenerator AddressGenerator { get; }

    private IEncryption Encryption { get; }

    /// <inheritdoc />
    /// TODO: move the contact information uploading to contact repository
    public async Task<CreateUserResponse> ExecuteAsync(CreateUserRequest request)
    {
      try
      {
        var publicKeyAddress = this.AddressGenerator.GetAddress(request.Seed, SecurityLevel.Medium, 0);

        var requestAddress = publicKeyAddress.GetChunk(0, Address.Length - 12)
          .Concat(publicKeyAddress.GetChunk(Address.Length - 12, 12).TryteStringIncrement());

        var ntruKeyPair = this.Encryption.CreateAsymmetricKeyPair(request.Seed.Value.ToLower(), publicKeyAddress.Value);
        var publicKeyTrytes = ntruKeyPair.PublicKey.ToBytes().EncodeBytesAsString();

        var requestAddressPayload = new TryteString(publicKeyTrytes + Constants.LineBreak + requestAddress.Value + Constants.End);

        await this.Messenger.SendMessageAsync(new Message(requestAddressPayload, publicKeyAddress));
        return new CreateUserResponse
                 {
                   Code = ResponseCode.Success,
                   NtruKeyPair = ntruKeyPair,
                   PublicKeyAddress = publicKeyAddress,
                   RequestAddress = new Address(requestAddress.Value)
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