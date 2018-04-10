namespace Chiota.IOTAServices
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services;
  using Chiota.ViewModels;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class IotaHelper
  {
    public static TryteString ObjectToTryteString<T>(T data)
    {
      var serializeObject = JsonConvert.SerializeObject(data);
      return TryteString.FromAsciiString(serializeObject);
    }

    public static bool CorrectSeedAdressChecker(string seed)
    {
      if (seed == null)
      {
        return false;
      }

      return seed != string.Empty && seed.All(c => "ABCDEFGHIJKLMNOPQRSTUVWXYZ9".Contains(c));
    }

    public static List<ChatMessage> FilterChatMessages(IEnumerable<TryteStringMessage> trytes, IAsymmetricKeyPair keyPair)
    {
      var chatMessages = new List<ChatMessage>();
      foreach (var tryte in trytes)
      {
        try
        {
          var trytesString = tryte.Message.ToString();
          var firstBreak = trytesString.IndexOf(ChiotaIdentifier.FirstBreak, StringComparison.Ordinal);
          var secondBreak = trytesString.IndexOf(ChiotaIdentifier.SecondBreak, StringComparison.Ordinal);
          var dateTrytes = new TryteString(trytesString.Substring(secondBreak + ChiotaIdentifier.SecondBreak.Length, trytesString.Length - secondBreak - ChiotaIdentifier.SecondBreak.Length));
          var date = DateTime.Parse(dateTrytes.ToUtf8String());

          var signature = trytesString.Substring(firstBreak + ChiotaIdentifier.FirstBreak.Length, 30);
          var messageTrytes = new TryteString(trytesString.Substring(0, firstBreak));
          var decryptedMessage = new NtruKex().Decrypt(keyPair, messageTrytes.ToBytes());
          var chatMessage = new ChatMessage { Message = decryptedMessage, Date = date, Signature = signature };
          chatMessages.Add(chatMessage);
        }
        catch
        {
          // ignored
        }
      }

      return chatMessages;
    }

    public static async Task<List<MessageViewModel>> GetNewMessages(IAsymmetricKeyPair keyPair, Contact contact, TangleMessenger tangle)
    {
      var messages = new List<MessageViewModel>();
      var encryptedMessages = await tangle.GetMessagesAsync(contact.ChatAdress);
      var messageList = FilterChatMessages(encryptedMessages, keyPair);

      if (messageList != null)
      {
        var sortedMessageList = messageList.OrderBy(o => o.Date).ToList();
        foreach (var message in sortedMessageList)
        {
          messages.Add(new MessageViewModel
                   {
                     Text = message.Message,
                     IsIncoming = message.Signature == contact.PublicKeyAdress.Substring(0, 30),
                     MessagDateTime = message.Date.ToLocalTime(),
                     ProfileImage = contact.ImageUrl
                   });
        }
      }

      return messages;
    }

    public static List<Hash> GetNewHashes(Tangle.Net.Repository.DataTransfer.TransactionHashList transactions, List<Hash> storedHashes)
    {
      var newHashes = new List<Hash>();
      foreach (var transactionsHash in transactions.Hashes)
      {
        var isStored = false;
        foreach (var storedHash in storedHashes)
        {
          if (transactionsHash.Value == storedHash.Value)
          {
            isStored = true;
            break;
          }
        }

        if (!isStored)
        {
          newHashes.Add(transactionsHash);
        }
      }

      return newHashes;
    }

    /// <summary>
    /// Filters Transactions for public key and contact address
    /// </summary>
    /// <param name="trytes">Transactions in List form</param>
    /// <returns>null if more than one key</returns>
    public static List<Contact> GetPublicKeysAndContactAddresses(IEnumerable<TryteStringMessage> trytes)
    {
      var contacts = new List<Contact>();
      foreach (var tryte in trytes)
      {
        var trytesString = tryte.Message.ToString();
        if (!trytesString.Contains(ChiotaIdentifier.LineBreak))
        {
          continue;
        }

        try
        {
          var index = trytesString.IndexOf(ChiotaIdentifier.LineBreak, StringComparison.Ordinal);
          var publicKeyString = trytesString.Substring(0, index);
          var bytesKey = new TryteString(publicKeyString).ToBytes();
          var contact = new Contact
                          {
                            PublicNtruKey = new NTRUPublicKey(bytesKey),
                            ContactAdress = trytesString.Substring(index + ChiotaIdentifier.LineBreak.Length, 81)
                          };
          contacts.Add(contact);
        }
        catch
        {
          // ignored
        }
      }

      return contacts;
    }
  }
}
