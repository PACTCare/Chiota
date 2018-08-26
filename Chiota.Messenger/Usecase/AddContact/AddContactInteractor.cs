namespace Chiota.Messenger.Usecase.AddContact
{
  using System;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  using Contact = Chiota.Messenger.Entity.Contact;

  /// <summary>
  /// The add contact interactor.
  /// </summary>
  public class AddContactInteractor : IUsecaseInteractor<AddContactRequest, AddContactResponse>
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="AddContactInteractor"/> class.
    /// </summary>
    /// <param name="repository">
    /// The repository.
    /// </param>
    /// <param name="messenger">
    /// The messenger.
    /// </param>
    /// <param name="contactInformationRepository">
    /// The contact Information Repository.
    /// </param>
    public AddContactInteractor(IContactRepository repository, IMessenger messenger, IContactInformationRepository contactInformationRepository)
    {
      this.Repository = repository;
      this.Messenger = messenger;
      this.ContactInformationRepository = contactInformationRepository;
    }

    /// <summary>
    /// Gets the repository.
    /// </summary>
    private IContactRepository Repository { get; }

    private IMessenger Messenger { get; }

    private IContactInformationRepository ContactInformationRepository { get; }

    /// <inheritdoc />
    public async Task<AddContactResponse> ExecuteAsync(AddContactRequest request)
    {
      try
      {
        var contactInformation = await this.ContactInformationRepository.LoadContactInformationByAddressAsync(request.ContactAddress);

        var requesterDetails = new Contact
                                 {
                                   ChatAddress = Seed.Random().ToString(),
                                   ChatKeyAddress = Seed.Random().ToString(),
                                   Name = request.Name,
                                   ImageHash = request.ImageHash,
                                   ContactAddress = request.RequestAddress.Value,
                                   Requested = true,
                                   Rejected = false,
                                   NtruKey = null,
                                   PublicKeyAddress = request.PublicKeyAddress.Value
                                 };

        await this.Messenger.SendMessageAsync(
          new Message(MessageType.RequestContact, TryteString.FromUtf8String(JsonConvert.SerializeObject(requesterDetails)), contactInformation.ContactAddress));

        var encryptedChatPasSalt = new NtruKeyExchange(NTRUParamSets.NTRUParamNames.A2011743).Encrypt(
          contactInformation.NtruKey,
          Encoding.UTF8.GetBytes(Seed.Random() + Seed.Random().ToString().Substring(0, 20)));

        await this.Messenger.SendMessageAsync(
          new Message(
            MessageType.KeyExchange,
            new TryteString(encryptedChatPasSalt.EncodeBytesAsString() + Constants.End),
            new Address(requesterDetails.ChatKeyAddress)));

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
  }
}