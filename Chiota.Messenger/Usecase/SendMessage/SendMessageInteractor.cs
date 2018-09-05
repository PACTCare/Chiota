using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Messenger.Usecase.SendMessage
{
  using System.Globalization;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Service;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  public class SendMessageInteractor : IUsecaseInteractor<SendMessageRequest, SendMessageResponse>
    {
      private IMessenger Messenger { get; }

      public SendMessageInteractor(IMessenger messenger)
      {
        this.Messenger = messenger;
      }

      /// <inheritdoc />
      public async Task<SendMessageResponse> ExecuteAsync(SendMessageRequest request)
      {
        if (request.Message.Length > Constants.MessageCharacterLimit)
        {
          return new SendMessageResponse { Code = ResponseCode.MessageTooLong };
        }

        var messageTimestamp = TryteString.FromUtf8String(DateTime.UtcNow.ToString(CultureInfo.InvariantCulture));
        var senderId = request.UserPublicKeyAddress.GetChunk(0, 30);
        var encryptedMessage = await Task.Run(
                                 () => new NtruKeyExchange(NTRUParamSets.NTRUParamNames.E1499EP1).Encrypt(
                                   request.KeyPair.PublicKey,
                                   Encoding.UTF8.GetBytes(request.Message)));

        var encryptedPayload = new TryteString(encryptedMessage.EncodeBytesAsString());
        var payloadSignature = Constants.FirstBreak.Concat(senderId).Concat(Constants.SecondBreak).Concat(messageTimestamp);

        var firstMessagePartPayload = encryptedPayload.GetChunk(0, 2070).Concat(payloadSignature).Concat(new TryteString("A")).Concat(Constants.End);
        var secondMessagePartPayload = new TryteString(encryptedPayload.Value.Substring(2070)).Concat(payloadSignature).Concat(new TryteString("B"))
          .Concat(Constants.End);

        await this.Messenger.SendMessageAsync(new Message(MessageType.ChatMessage, firstMessagePartPayload, request.ChatAddress));
        await this.Messenger.SendMessageAsync(new Message(MessageType.ChatMessage, secondMessagePartPayload, request.ChatAddress));

        return new SendMessageResponse { Code = ResponseCode.Success };
      }
    }
}
