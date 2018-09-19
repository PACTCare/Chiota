namespace Chiota.Messenger.Usecase.GetMessages
{
  using System;
  using System.Collections.Generic;
  using System.Globalization;
  using System.Linq;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  public class GetMessagesInteractor : IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>
  {
    public GetMessagesInteractor(IMessenger messenger)
    {
      this.Messenger = messenger;
    }

    private IMessenger Messenger { get; }

    /// <inheritdoc />
    public async Task<GetMessagesResponse> ExecuteAsync(GetMessagesRequest request)
    {
      var rawMessages = await this.Messenger.GetMessagesByAddressAsync(request.ChatAddress, new MessageBundleParser());

      var encryptedMessages = rawMessages.Select(ReadChatMessage).ToList();
      var sortedEncryptedMessages = encryptedMessages.OrderBy(o => o.Date).ToList();

      var decryptedMessages = new List<ChatMessage>();
      for (var i = 0; i < sortedEncryptedMessages.Count - 1; i = i + 2)
      {
        if (HasMessageTwoParts(sortedEncryptedMessages, i))
        {
          var encryptedMessage = sortedEncryptedMessages[i].IsFirstPart
                                   ? new TryteString(sortedEncryptedMessages[i].Message + sortedEncryptedMessages[i + 1].Message)
                                   : new TryteString(sortedEncryptedMessages[i + 1].Message + sortedEncryptedMessages[i].Message);

          var decryptedMessage = Encoding.UTF8.GetString(
            new NtruKeyExchange(NTRUParamSets.NTRUParamNames.E1499EP1).Decrypt(request.ChatKeyPair, encryptedMessage.DecodeBytesFromTryteString()));

          decryptedMessages.Add(
            new ChatMessage { Date = sortedEncryptedMessages[i].Date, Message = decryptedMessage, Signature = sortedEncryptedMessages[i].Signature });
        }
        else
        {
          i--;
        }
      }

      return new GetMessagesResponse { Code = ResponseCode.Success, Messages = decryptedMessages };
    }

    private static bool HasMessageTwoParts(IReadOnlyList<ChatMessage> sortedEncryptedMessages, int i)
    {
      return sortedEncryptedMessages[i].IsFirstPart != sortedEncryptedMessages[i + 1].IsFirstPart;
    }

    private static ChatMessage ReadChatMessage(Message message)
    {
      var messagePayload = message.Payload.Value;
      var firstBreakIndex = messagePayload.IndexOf(Constants.FirstBreak.Value, StringComparison.Ordinal);
      var secondBreakIndex = messagePayload.IndexOf(Constants.SecondBreak.Value, StringComparison.Ordinal);

      var dateTrytes = new TryteString(
        messagePayload.Substring(
          secondBreakIndex + Constants.SecondBreak.Value.Length,
          messagePayload.Length - secondBreakIndex - Constants.SecondBreak.Value.Length - 1));

      return new ChatMessage
               {
                 Message = messagePayload.Substring(0, firstBreakIndex),
                 Date = DateTime.Parse(dateTrytes.ToUtf8String(), CultureInfo.InvariantCulture),
                 Signature = messagePayload.Substring(firstBreakIndex + Constants.FirstBreak.Value.Length, 30),
                 IsFirstPart = messagePayload[messagePayload.Length - 1] == 'A'
               };
    }
  }
}