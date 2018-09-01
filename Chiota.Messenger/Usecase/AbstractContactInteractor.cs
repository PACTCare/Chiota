namespace Chiota.Messenger.Usecase
{
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  /// <inheritdoc />
  public abstract class AbstractContactInteractor<TIn, T> : IUsecaseInteractor<TIn, T>
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="AbstractContactInteractor{TIn,T}"/> class. 
    /// </summary>
    /// <param name="repository">
    /// The repository.
    /// </param>
    /// <param name="messenger">
    /// The messenger.
    /// </param>
    public AbstractContactInteractor(IContactRepository repository, IMessenger messenger)
    {
      this.Repository = repository;
      this.Messenger = messenger;
    }

    /// <summary>
    /// Gets the messenger.
    /// </summary>
    protected IMessenger Messenger { get; }

    /// <summary>
    /// Gets the repository.
    /// </summary>
    protected IContactRepository Repository { get; }

    /// <inheritdoc />
    public abstract Task<T> ExecuteAsync(TIn request);

    /// <summary>
    /// The exchange key.
    /// </summary>
    /// <param name="requesterDetails">
    /// The requester details.
    /// </param>
    /// <param name="contactInformation">
    /// The contact information.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    protected async Task ExchangeKey(Contact requesterDetails, ContactInformation contactInformation)
    {
      var encryptedChatPasSalt = new NtruKeyExchange(NTRUParamSets.NTRUParamNames.A2011743).Encrypt(
        contactInformation.NtruKey,
        Encoding.UTF8.GetBytes(Seed.Random() + Seed.Random().ToString().Substring(0, 20)));

      await this.Messenger.SendMessageAsync(
        new Message(
          MessageType.KeyExchange,
          new TryteString(encryptedChatPasSalt.EncodeBytesAsString() + Constants.End),
          new Address(requesterDetails.ChatKeyAddress)));
    }

    /// <summary>
    /// The send contact details.
    /// </summary>
    /// <param name="messageType">
    /// The message type.
    /// </param>
    /// <param name="details">
    /// The details.
    /// </param>
    /// <param name="receiver">
    /// The receiver.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    protected async Task SendContactDetails(string messageType, Contact details, Address receiver)
    {
      await this.Messenger.SendMessageAsync(new Message(messageType, TryteString.FromUtf8String(JsonConvert.SerializeObject(details)), receiver));
    }
  }
}