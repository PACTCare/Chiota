namespace Chiota.Messenger.Usecase.AddContact
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  using Tangle.Net.Entity;

  /// <inheritdoc />
  public class AddContactInteractor : AbstractContactInteractor<AddContactRequest, AddContactResponse>
  {
    /// <inheritdoc />
    public AddContactInteractor(IContactRepository repository, IMessenger messenger)
      : base(repository, messenger, null)
    {
    }

    /// <inheritdoc />
    public override async Task<AddContactResponse> ExecuteAsync(AddContactRequest request)
    {
      try
      {
        var requesterDetails = new Contact
                                 {
                                   ChatAddress = Seed.Random().ToString(),
                                   ChatKeyAddress = Seed.Random().ToString(),
                                   Name = request.Name,
                                   ImageHash = request.ImagePath,
                                   ContactAddress = request.RequestAddress.Value,
                                   Request = true,
                                   Rejected = false,
                                   NtruKey = null,
                                   PublicKeyAddress = request.PublicKeyAddress.Value
                                 };

        var contactInformation = await this.Repository.LoadContactInformationByAddressAsync(request.ContactAddress);

        await this.SendContactDetails(requesterDetails, contactInformation);
        await this.ExchangeKey(requesterDetails, contactInformation.NtruKey, GetChatPasSalt());

        await this.Repository.AddContactAsync(requesterDetails.ChatAddress, true, requesterDetails.PublicKeyAddress);

        return new AddContactResponse { Code = ResponseCode.Success };
      }
      catch (MessengerException exception)
      {
        return new AddContactResponse { Code = exception.Code };
      }
      catch (Exception)
      {
        return new AddContactResponse { Code = ResponseCode.UnkownException };
      }
    }

    /// <summary>
    /// The get chat pas salt.
    /// </summary>
    /// <returns>
    /// The <see cref="string"/>.
    /// </returns>
    private static string GetChatPasSalt()
    {
      return Seed.Random() + Seed.Random().ToString().Substring(0, 20);
    }
  }
}