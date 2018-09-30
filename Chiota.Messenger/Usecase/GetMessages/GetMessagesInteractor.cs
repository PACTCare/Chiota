namespace Chiota.Messenger.Usecase.GetMessages
{
  using System;
  using System.Collections.Generic;
  using System.Globalization;
  using System.Linq;
  using System.Text;
  using System.Text.RegularExpressions;
  using System.Threading.Tasks;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class GetMessagesInteractor : IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>
  {
    public GetMessagesInteractor(IMessenger messenger, IEncryption encryption)
    {
      this.Messenger = messenger;
      this.Encryption = encryption;
    }

    private IEncryption Encryption { get; }

    private IMessenger Messenger { get; }

    private Address CurrentChatAddress { get; set; }

    /// <inheritdoc />
    public async Task<GetMessagesResponse> ExecuteAsync(GetMessagesRequest request)
    {
      try
      {
        this.CurrentChatAddress = request.ChatAddress;
        var messages = await this.LoadMessagesOnAddressAsync(request.ChatKeyPair);
        return new GetMessagesResponse { Code = ResponseCode.Success, Messages = messages, CurrentChatAddress = this.CurrentChatAddress };
      }
      catch (MessengerException exception)
      {
        return new GetMessagesResponse { Code = exception.Code };
      }
    }

    /// <summary>
    /// Generates a new chat address base on previous encrypted messages
    /// </summary>
    /// <param name="contactAddress">
    /// Current chat address
    /// </param>
    /// <param name="messages">
    /// Encrypted Messages 
    /// </param>
    /// <returns>
    /// New chat address
    /// </returns>
    private static Address GenerateNextAddress(Address contactAddress, List<ChatMessage> messages)
    {
      if (messages.Count <= 3)
      {
        return contactAddress;
      }

      var rgx = new Regex("[^A-Z]");
      var increment = contactAddress.GetChunk(0, 15).TryteStringIncrement();

      var str = increment + rgx.Replace(messages[messages.Count - 1].Message.ToUpper(), string.Empty)
                          + rgx.Replace(messages[messages.Count - 3].Message.ToUpper(), string.Empty) + rgx.Replace(
                            messages[messages.Count - 2].Message.ToUpper(),
                            string.Empty);
      str = str.Truncate(70);
      return new Address(str + contactAddress.Value.Substring(str.Length));
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

    private async Task<List<ChatMessage>> LoadMessagesOnAddressAsync(IAsymmetricKeyPair chatKeyPair)
    {
      var rawMessages = await this.Messenger.GetMessagesByAddressAsync(this.CurrentChatAddress, new MessageBundleParser());
      var parsedMessages = ReadChatMessages(rawMessages);

      var decryptedMessages = new List<ChatMessage>();
      for (var i = 0; i < parsedMessages.Count - 1; i = i + 2)
      {
        if (HasMessageTwoParts(parsedMessages, i))
        {
          var encryptedMessage = parsedMessages[i].IsFirstPart
                                   ? new TryteString(parsedMessages[i].Message + parsedMessages[i + 1].Message)
                                   : new TryteString(parsedMessages[i + 1].Message + parsedMessages[i].Message);

          var decryptedMessage = Encoding.UTF8.GetString(this.Encryption.Decrypt(chatKeyPair, encryptedMessage.DecodeBytesFromTryteString()));

          decryptedMessages.Add(new ChatMessage { Date = parsedMessages[i].Date, Message = decryptedMessage, Signature = parsedMessages[i].Signature });
        }
        else
        {
          i--;
        }
      }

      if (decryptedMessages.Count < Constants.MaxMessagesOnAddress)
      {
        return decryptedMessages;
      }

      this.CurrentChatAddress = GenerateNextAddress(this.CurrentChatAddress, decryptedMessages);
      decryptedMessages.AddRange(await this.LoadMessagesOnAddressAsync(chatKeyPair));
      return decryptedMessages;
    }
  }
}