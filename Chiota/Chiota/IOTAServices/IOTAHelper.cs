namespace Chiota.IOTAServices
{
  using System;
  using System.Collections.Generic;
  using System.Globalization;
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
          var firstBreakIndex = trytesString.IndexOf(ChiotaConstants.FirstBreak, StringComparison.Ordinal);
          var secondBreakIndex = trytesString.IndexOf(ChiotaConstants.SecondBreak, StringComparison.Ordinal);
          var dateTrytes = new TryteString(trytesString.Substring(secondBreakIndex + ChiotaConstants.SecondBreak.Length, trytesString.Length - secondBreakIndex - ChiotaConstants.SecondBreak.Length));
          var date = DateTime.Parse(dateTrytes.ToUtf8String(), CultureInfo.InvariantCulture);

          var signature = trytesString.Substring(firstBreakIndex + ChiotaConstants.FirstBreak.Length, 30);
          var messageTrytes = new TryteString(trytesString.Substring(0, firstBreakIndex));

          // todo decrypt doesn't work for Jana
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

    public static List<Contact> FilterApprovedContacts(
      IEnumerable<TryteStringMessage> trytes,
      IAsymmetricKeyPair keyPair)
    {
      var approvedContacts = new List<Contact>();
      foreach (var tryte in trytes)
      {
        try
        {
          var decryptedMessage = new NtruKex().Decrypt(keyPair, tryte.Message.ToBytes());

          var chatAddress = decryptedMessage.Substring(0, 81);

          // length accepted = rejected 
          var substring = decryptedMessage.Substring(81, ChiotaConstants.Rejected.Length);      

          var contact = new Contact { ChatAddress = chatAddress };
          if (substring.Contains(ChiotaConstants.Accepted))
          {
            contact.Rejected = false;
          }
          else if (substring.Contains(ChiotaConstants.Rejected))
          {
            contact.Rejected = true;
          }
          else
          {
            continue;
          }

          approvedContacts.Add(contact);
        }
        catch
        {
          // ignored
        }
      }

      return approvedContacts;
    }

    public static async Task<List<MessageViewModel>> GetNewMessages(IAsymmetricKeyPair keyPair, Contact contact, TangleMessenger tangle)
    {
      var messages = new List<MessageViewModel>();
      var encryptedMessages = await tangle.GetMessagesAsync(contact.ChatAddress);

      var messageList = FilterChatMessages(encryptedMessages, keyPair);

      if (messageList != null)
      {
        var sortedMessageList = messageList.OrderBy(o => o.Date).ToList();
        foreach (var message in sortedMessageList)
        {
          messages.Add(new MessageViewModel
                   {
                     Text = message.Message,
                     IsIncoming = message.Signature == contact.PublicKeyAddress.Substring(0, 30),
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
        if (!trytesString.Contains(ChiotaConstants.LineBreak))
        {
          continue;
        }

        try
        {
          var index = trytesString.IndexOf(ChiotaConstants.LineBreak, StringComparison.Ordinal);
          var publicKeyString = trytesString.Substring(0, index);
          var bytesKey = new TryteString(publicKeyString).ToBytes();
          var contact = new Contact
                          {
                            PublicNtruKey = new NTRUPublicKey(bytesKey),
                            ContactAddress = trytesString.Substring(index + ChiotaConstants.LineBreak.Length, 81)
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
