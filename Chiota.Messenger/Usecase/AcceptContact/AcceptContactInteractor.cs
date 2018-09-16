namespace Chiota.Messenger.Usecase.AcceptContact
{
  using System;
  using System.Collections.Generic;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The accept contact interactor.
  /// </summary>
  public class AcceptContactInteractor : AbstractContactInteractor<AcceptContactRequest, AcceptContactResponse>
  {
    /// <inheritdoc />
    public AcceptContactInteractor(IContactRepository repository, IMessenger messenger)
      : base(repository, messenger)
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

    /// <summary>
    /// The get chat password salt.
    /// TODO: This is currently not testable and needs to be put in some kind of crypto class
    /// </summary>
    /// <param name="chatKeyAddress">
    /// The chat key address.
    /// </param>
    /// <param name="userKeyPair">
    /// The user key pair.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task<string> GetChatPasswordSalt(Address chatKeyAddress, IAsymmetricKeyPair userKeyPair)
    {
      var messages = await this.Messenger.GetMessagesByAddressAsync(chatKeyAddress, new MessageBundleParser());
      var chatPasSalt = new List<string>();
      foreach (var message in messages)
      {
        try
        {
          var pasSalt = Encoding.UTF8.GetString(
            new NtruKeyExchange(NTRUParamSets.NTRUParamNames.A2011743).Decrypt(userKeyPair, message.Payload.DecodeBytesFromTryteString()));
          if (pasSalt != string.Empty)
          {
            chatPasSalt.Add(pasSalt);
          }
        }
        catch
        {
          // ignored
        }
      }

      if (chatPasSalt.Count > 0)
      {
        return chatPasSalt[0];
      }

      throw new MessengerException(ResponseCode.ChatPasswordAndSaltCannotBeGenerated);
    }
  }
}