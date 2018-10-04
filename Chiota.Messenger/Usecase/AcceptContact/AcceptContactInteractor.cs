namespace Chiota.Messenger.Usecase.AcceptContact
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  /// <summary>
  /// The accept contact interactor.
  /// </summary>
  public class AcceptContactInteractor : AbstractContactInteractor<AcceptContactRequest, AcceptContactResponse>
  {
    /// <inheritdoc />
    public AcceptContactInteractor(IContactRepository repository, IMessenger messenger, IEncryption encryption)
      : base(repository, messenger, encryption)
    {
    }

    /// <inheritdoc />
    public override async Task<AcceptContactResponse> ExecuteAsync(AcceptContactRequest request)
    {
      try
      {
        var contactDetails = new Contact
                               {
                                 Name = request.UserName,
                                 ImageHash = request.UserImageHash,
                                 ChatAddress = request.ChatAddress.Value,
                                 ChatKeyAddress = request.ChatKeyAddress.Value,
                                 ContactAddress = null,
                                 PublicKeyAddress = request.UserPublicKeyAddress.Value,
                                 Rejected = false,
                                 Request = false,
                                 NtruKey = null
                               };

        // Generate chat pass salt here so we exit the interactor when it fails, before sending something
        var chatPasSalt = await this.GetChatPasswordSalt(request.ChatKeyAddress, request.UserKeyPair);

        var contactInformation = await this.Repository.LoadContactInformationByAddressAsync(request.ContactPublicKeyAddress);
        await this.SendContactDetails(contactDetails, request.ContactAddress);
        await this.ExchangeKey(contactDetails, contactInformation.NtruKey, chatPasSalt);

        await this.Repository.AddContactAsync(request.ChatAddress.Value, true, contactDetails.PublicKeyAddress);
        return new AcceptContactResponse { Code = ResponseCode.Success };
      }
      catch (MessengerException exception)
      {
        return new AcceptContactResponse { Code = exception.Code };
      }
      catch (Exception)
      {
        return new AcceptContactResponse { Code = ResponseCode.UnkownException };
      }
    }
  }
}