namespace Chiota.Messenger.Usecase.GetMessages
{
  using System;
  using System.Collections.Generic;
  using System.Globalization;
  using System.Linq;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
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
      try
      {
        var rawMessages = await this.Messenger.GetMessagesByAddressAsync(request.ChatAddress, new MessageBundleParser());
        var parsedMessages = ReadChatMessages(rawMessages);

        var decryptedMessages = new List<ChatMessage>();
        for (var i = 0; i < parsedMessages.Count - 1; i = i + 2)
        {
          if (HasMessageTwoParts(parsedMessages, i))
          {
            var encryptedMessage = parsedMessages[i].IsFirstPart
                                     ? new TryteString(parsedMessages[i].Message + parsedMessages[i + 1].Message)
                                     : new TryteString(parsedMessages[i + 1].Message + parsedMessages[i].Message);

            var decryptedMessage = Encoding.UTF8.GetString(
              new NtruKeyExchange(NTRUParamSets.NTRUParamNames.E1499EP1).Decrypt(request.ChatKeyPair, encryptedMessage.DecodeBytesFromTryteString()));

            decryptedMessages.Add(
              new ChatMessage { Date = parsedMessages[i].Date, Message = decryptedMessage, Signature = parsedMessages[i].Signature });
          }
          else
          {
            i--;
          }
        }

        return new GetMessagesResponse { Code = ResponseCode.Success, Messages = decryptedMessages };
      }
      catch (MessengerException exception)
      {
        return new GetMessagesResponse { Code = exception.Code };
      }
    }

    private static bool HasMessageTwoParts(IReadOnlyList<ChatMessage> sortedEncryptedMessages, int i)
    {
      return sortedEncryptedMessages[i].IsFirstPart != sortedEncryptedMessages[i + 1].IsFirstPart;
    }

    private static List<ChatMessage> ReadChatMessages(IEnumerable<Message> messages)
    {
      var parsedMessages = new List<ChatMessage>();
      foreach (var message in messages)
      {
        var messagePayload = message.Payload.Value;
        var firstBreakIndex = messagePayload.IndexOf(Constants.FirstBreak.Value, StringComparison.Ordinal);
        var secondBreakIndex = messagePayload.IndexOf(Constants.SecondBreak.Value, StringComparison.Ordinal);

        if (firstBreakIndex == -1 || secondBreakIndex == -1)
        {
          continue;
        }

        var dateTrytes = new TryteString(
          messagePayload.Substring(
            secondBreakIndex + Constants.SecondBreak.Value.Length,
            messagePayload.Length - secondBreakIndex - Constants.SecondBreak.Value.Length - 1));

        parsedMessages.Add(
          new ChatMessage
            {
              Message = messagePayload.Substring(0, firstBreakIndex),
              Date = DateTime.Parse(dateTrytes.ToUtf8String(), CultureInfo.InvariantCulture),
              Signature = messagePayload.Substring(firstBreakIndex + Constants.FirstBreak.Value.Length, 30),
              IsFirstPart = messagePayload[messagePayload.Length - 1] == 'A'
            });
      }

      return parsedMessages.OrderBy(o => o.Date).ToList();
    }
  }
}