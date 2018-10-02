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

  public class SendMessageInteractor : IUsecaseInteractor<SendMessageRequest, SendMessageResponse>
  {
    public SendMessageInteractor(IMessenger messenger, IEncryption encryption)
    {
      this.Messenger = messenger;
      this.Encryption = encryption;
    }

    private IMessenger Messenger { get; }

    private IEncryption Encryption { get; }

    /// <inheritdoc />
    public async Task<SendMessageResponse> ExecuteAsync(SendMessageRequest request)
    {
      try
      {
        if (request.Message.Length > Constants.MessageCharacterLimit)
        {
          return new SendMessageResponse { Code = ResponseCode.MessageTooLong };
        }

        var chatMessage = new ChatMessage
                            {
                              Date = DateTime.UtcNow,
                              Message = request.Message,
                              Signature = request.UserPublicKeyAddress.GetChunk(0, 30).Value
                            };

        var encryptedMessage = await Task.Run(
                                 () => this.Encryption.Encrypt(
                                   request.KeyPair.PublicKey,
                                   Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(chatMessage))));

        await this.Messenger.SendMessageAsync(new Message(encryptedMessage.ToTrytes(), request.ChatAddress));

        return new SendMessageResponse { Code = ResponseCode.Success };
      }
      catch (MessengerException exception)
      {
        return new SendMessageResponse { Code = exception.Code };
      }
    }
  }
}