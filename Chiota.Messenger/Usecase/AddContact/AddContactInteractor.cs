namespace Chiota.Messenger.Usecase.AddContact
{
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
    public AddContactInteractor(IContactRepository repository, IMessenger messenger)
    {
      this.Repository = repository;
      this.Messenger = messenger;
    }

    /// <summary>
    /// Gets the repository.
    /// </summary>
    private IContactRepository Repository { get; }

    private IMessenger Messenger { get; }

    /// <inheritdoc />
    public async Task<AddContactResponse> ExecuteAsync(AddContactRequest request)
    {
      try
      {
        var contact = new Contact { ContactAddress = request.ContactAddress.Value };

        await this.Messenger.SendMessageAsync(
          new Message(MessageType.RequestContact, TryteString.FromUtf8String(JsonConvert.SerializeObject(contact)), request.ContactAddress));

        var encryptedChatPasSalt = new NtruKeyExchange(NTRUParamSets.NTRUParamNames.A2011743).Encrypt(
          request.NtruKey,
          Encoding.UTF8.GetBytes(Seed.Random() + Seed.Random().ToString().Substring(0, 20)));

        await this.Messenger.SendMessageAsync(
          new Message(
            MessageType.KeyExchange,
            new TryteString(encryptedChatPasSalt.EncodeBytesAsString() + Constants.End),
            request.ContactAddress));

        await this.Repository.AddContactAsync(contact);

        return new AddContactResponse { Code = ResponseCode.Success };
      }
      catch (MessengerException exception)
      {
        return new AddContactResponse { Code = exception.Code };
      }
    }
  }
}