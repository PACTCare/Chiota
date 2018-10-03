namespace Chiota.Messenger.Usecase
{
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Extensions;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <inheritdoc />
  public abstract class AbstractContactInteractor<TIn, T> : AbstractChatInteractor<TIn, T>
    where T : BaseResponse
  {
    protected AbstractContactInteractor(IContactRepository repository, IMessenger messenger, IEncryption keyEncryption)
      : base(messenger, keyEncryption)
    {
      this.Repository = repository;
      this.Messenger = messenger;
    }

    protected IMessenger Messenger { get; }

    protected IContactRepository Repository { get; }

    protected async Task ExchangeKey(Contact requesterDetails, IAsymmetricKey ntruKey, string chatPasSalt)
    {
      var encryptedChatPasSalt = NtruEncryption.Key.Encrypt(ntruKey, Encoding.UTF8.GetBytes(chatPasSalt));

      await this.Messenger.SendMessageAsync(
        new Message(new TryteString(encryptedChatPasSalt.EncodeBytesAsString() + Constants.End), new Address(requesterDetails.ChatKeyAddress)));
    }

    protected async Task SendContactDetails(Contact details, Address receiver)
    {
      await this.Messenger.SendMessageAsync(new Message(TryteString.FromUtf8String(JsonConvert.SerializeObject(details)), receiver));
    }
  }
}