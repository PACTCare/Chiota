namespace Chiota.Messenger.Usecase.CheckUser
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;

  public class CheckUserInteractor : AbstractUserInteractor<CheckUserRequest, CheckUserResponse>
  {
    public CheckUserInteractor(
      IContactRepository contactRepository,
      IMessenger messenger,
      IAddressGenerator addressGenerator,
      ISignatureFragmentGenerator signatureGenerator)
      : base(signatureGenerator)
    {
      this.ContactRepository = contactRepository;
      this.Messenger = messenger;
      this.AddressGenerator = addressGenerator;
    }

    private IAddressGenerator AddressGenerator { get; }

    private IContactRepository ContactRepository { get; }

    private IMessenger Messenger { get; }

    /// <inheritdoc />
    public override async Task<CheckUserResponse> ExecuteAsync(CheckUserRequest request)
    {
      try
      {
        var checkUserResult = await this.LoadUserInformationAsync(request.PublicKeyAddress);
        if (checkUserResult != ResponseCode.NoContactInformationPresent)
        {
          return new CheckUserResponse { Code = checkUserResult };
        }

        // The address needs to be generated newly so we have access to its private key
        var publicKeyAddress = await this.AddressGenerator.GetAddressAsync(request.Seed, Constants.MessengerSecurityLevel, 0);
        var payload = await this.CreateSignedPublicKeyPayloadAsync(request.PublicKey, request.RequestAddress, publicKeyAddress.PrivateKey);
        await this.Messenger.SendMessageAsync(new Message(payload, publicKeyAddress));

        return new CheckUserResponse { Code = ResponseCode.Success };
      }
      catch (MessengerException exception)
      {
        return new CheckUserResponse { Code = exception.Code };
      }
      catch (Exception)
      {
        return new CheckUserResponse { Code = ResponseCode.UnkownException };
      }
    }

    private async Task<ResponseCode> LoadUserInformationAsync(Address publicKeyAddress)
    {
      try
      {
        await this.ContactRepository.LoadContactInformationByAddressAsync(publicKeyAddress);
      }
      catch (MessengerException exception)
      {
        return exception.Code;
      }

      return ResponseCode.Success;
    }
  }
}