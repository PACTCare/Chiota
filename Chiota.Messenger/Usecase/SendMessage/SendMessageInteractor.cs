namespace Chiota.Messenger.Usecase.SendMessage
{
  using System;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service;

  using Newtonsoft.Json;

  using Tangle.Net.Utils;

  using Constants = Constants;

  public class SendMessageInteractor : AbstractChatInteractor<SendMessageRequest, SendMessageResponse>
  {
    public SendMessageInteractor(IMessenger messenger, IEncryption messageEncryption, IEncryption keyEncryption)
      : base(messenger, keyEncryption)
    {
      this.Messenger = messenger;
      this.Encryption = messageEncryption;
    }

    private IMessenger Messenger { get; }

    private IEncryption Encryption { get; }

    /// <inheritdoc />
    public override async Task<SendMessageResponse> ExecuteAsync(SendMessageRequest request)
    {
      try
      {
        if (request.Message.Length > Constants.MessageCharacterLimit)
        {
          return new SendMessageResponse { Code = ResponseCode.MessageTooLong };
        }

        if (request.ChatKeyPair == null)
        {
          var pasSalt = await this.GetChatPasswordSalt(request.ChatKeyAddress, request.UserKeyPair);
          request.ChatKeyPair = this.Encryption.CreateAsymmetricKeyPair(pasSalt.Substring(0, 50), pasSalt.Substring(50, 50));
        }

        var chatMessage = new ChatMessage
                            {
                              Date = DateTime.UtcNow,
                              Message = request.Message,
                              Signature = request.UserPublicKeyAddress.GetChunk(0, 30).Value
                            };

        var encryptedMessage = await Task.Run(
                                 () => this.Encryption.Encrypt(
                                   request.ChatKeyPair.PublicKey,
                                   Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(chatMessage))));

        await this.Messenger.SendMessageAsync(new Message(encryptedMessage.ToTrytes(), request.ChatAddress));

        return new SendMessageResponse { Code = ResponseCode.Success, ChatKeyPair = request.ChatKeyPair };
      }
      catch (MessengerException exception)
      {
        return new SendMessageResponse { Code = exception.Code };
      }
    }
  }
}