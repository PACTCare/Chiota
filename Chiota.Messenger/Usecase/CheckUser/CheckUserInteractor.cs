namespace Chiota.Messenger.Usecase.CheckUser
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;

  public class CheckUserInteractor : IUsecaseInteractor<CheckUserRequest, CheckUserResponse>
  {
    public CheckUserInteractor(IContactRepository contactRepository, IMessenger messenger, IAddressGenerator addressGenerator)
    {
      this.ContactRepository = contactRepository;
      this.Messenger = messenger;
      this.AddressGenerator = addressGenerator;
    }

    private IAddressGenerator AddressGenerator { get; }

    private IContactRepository ContactRepository { get; }

    private IMessenger Messenger { get; }

    /// <inheritdoc />
    public async Task<CheckUserResponse> ExecuteAsync(CheckUserRequest request)
    {
      try
      {
        var contactInformationPayload = new TryteString(
          request.PublicKey.ToBytes().EncodeBytesAsString() + Constants.LineBreak + request.RequestAddress + Constants.End);

        var checkUserResult = await this.LoadUserInformationAsync(request.PublicKeyAddress);
        switch (checkUserResult)
        {
          case ResponseCode.AmbiguousContactInformation:
            // The public key address has invalid transactions on it. We'll find a new one
            return await this.UploadContactInformationToNewAddressAsync(
                                        contactInformationPayload,
                                        request.PublicKeyAddress,
                                        request.Seed);
          case ResponseCode.NoContactInformationPresent:
            // A snapshot may have happened, so we reupload the contact information
            await this.Messenger.SendMessageAsync(new Message(contactInformationPayload, request.PublicKeyAddress));
            break;
          default:
            return new CheckUserResponse { Code = checkUserResult };
        }

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

    private async Task<CheckUserResponse> UploadContactInformationToNewAddressAsync(TryteString payload, TryteString publicKeyAddress, TryteString seed)
    {
      var newSeed = seed.Value.Substring(0, 75) + publicKeyAddress.Value.Substring(0, 6);
      var newPublicKeyAddress = this.AddressGenerator.GetAddress(new Seed(newSeed), SecurityLevel.Medium, 0);

      var resultState = await this.LoadUserInformationAsync(newPublicKeyAddress);
      if (resultState == ResponseCode.Success)
      {
        return new CheckUserResponse { Code = ResponseCode.NewPublicKeyAddress, PublicKeyAddress = newPublicKeyAddress };
      }

      if (resultState != ResponseCode.NoContactInformationPresent)
      {
        return await this.UploadContactInformationToNewAddressAsync(payload, newPublicKeyAddress, seed);
      }

      await this.Messenger.SendMessageAsync(new Message(payload, newPublicKeyAddress));

      return new CheckUserResponse { Code = ResponseCode.NewPublicKeyAddress, PublicKeyAddress = newPublicKeyAddress };
    }
  }
}