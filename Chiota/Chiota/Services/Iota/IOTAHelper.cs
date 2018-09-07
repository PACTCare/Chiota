namespace Chiota.Services.Iota
{
  using System;
  using System.Collections.Generic;
  using System.Globalization;
  using System.Linq;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Models;
  using Chiota.Services;
  using Chiota.ViewModels;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The iota helper.
  /// </summary>
  public static class IotaHelper
  {
    /// <summary>
    /// The extract message.
    /// </summary>
    /// <param name="bundle">
    /// The bundle.
    /// </param>
    /// <returns>
    /// The <see cref="TryteString"/>.
    /// </returns>
    public static TryteString ExtractMessage(Bundle bundle)
    {
      var messageTrytes = string.Empty;

      // multiple message per bundle?
      foreach (var transaction in bundle.Transactions)
      {
        if (transaction.Value < 0)
        {
          continue;
        }

        if (!transaction.Fragment.IsEmpty)
        {
          messageTrytes += transaction.Fragment.Value;
        }
      }

      if (!messageTrytes.Contains(ChiotaConstants.End))
      {
        return null;
      }

      var index = messageTrytes.IndexOf(ChiotaConstants.End, StringComparison.Ordinal);
      return new TryteString(messageTrytes.Substring(0, index));
    }

    public static async Task<List<MessageViewModel>> GetNewMessages(IAsymmetricKeyPair keyPair, Contact contact, TangleMessenger tangle)
    {
      var trytes = await tangle.GetMessagesAsync(contact.ChatAddress, 3, true);
      var messagesEncrypted = new List<ChatMessage>();
      foreach (var tryte in trytes)
      {
        try
        {
          messagesEncrypted.Add(ReadChatMessage(tryte));
        }
        catch
        {
          // ignored
        }
      }

      var sortedEncryptedMessages = messagesEncrypted.OrderBy(o => o.Date).ToList();
      var messages = new List<MessageViewModel>();

      for (var i = 0; i < sortedEncryptedMessages.Count - 1; i = i + 2)
      {
        if (TwoPartsOfMessage(sortedEncryptedMessages, i))
        {
          TryteString encryptedMessage;
          if (sortedEncryptedMessages[i].IsFirstPart)
          {
            encryptedMessage = new TryteString(sortedEncryptedMessages[i].Message + sortedEncryptedMessages[i + 1].Message);
          }
          else
          {
            encryptedMessage = new TryteString(sortedEncryptedMessages[i + 1].Message + sortedEncryptedMessages[i].Message);
          }

          var decryptedMessage = Encoding.UTF8.GetString(new NtruKex().Decrypt(keyPair, encryptedMessage.DecodeBytesFromTryteString()));
          messages.Add(new MessageViewModel
          {
            Text = decryptedMessage,
            MessagDateTime = sortedEncryptedMessages[i].Date.ToLocalTime(),
            IsIncoming = sortedEncryptedMessages[i].Signature == contact.PublicKeyAddress.Substring(0, 30),
            ProfileImage = contact.ImageHash
          });
        }
        else
        {
          i--;
        }
      }

      return messages;
    }

    public static async Task<List<Contact>> GetPublicKeysAndContactAddresses(TangleMessenger tangleMessenger, string receiverAddress, bool dontLoadSql = false)
    {
      var trytes = await tangleMessenger.GetMessagesAsync(receiverAddress, 3, false, dontLoadSql);
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
          var bytesKey = new TryteString(publicKeyString).DecodeBytesFromTryteString();

          contacts.Add(
            new Contact
            {
              NtruKey = new NTRUPublicKey(bytesKey),
              ContactAddress = trytesString.Substring(index + ChiotaConstants.LineBreak.Length, 81)
            });
        }
        catch
        {
          // ignored
        }
      }

      return RemoveDuplicateContacts(contacts);
    }

    public static async Task<string> GetChatPasSalt(User user, string chatKeyAddress)
    {
      // Todo sometimes only one tryte
      var trytes = await user.TangleMessenger.GetMessagesAsync(chatKeyAddress, 3, false, false, true);
      var chatPasSalt = new List<string>();
      foreach (var tryte in trytes)
      {
        try
        {
          var pasSalt = Encoding.UTF8.GetString(
            new NtruKex(true).Decrypt(user.NtruKeyPair, tryte.Message.DecodeBytesFromTryteString()));
          if (pasSalt != string.Empty)
          {
            chatPasSalt.Add(pasSalt);
          }
        }
        catch
        {
          // ignored
        }
      }

      if (chatPasSalt.Count > 0)
      {
        return chatPasSalt[0];
      }

      return null;
    }

    private static ChatMessage ReadChatMessage(TryteStringMessage tryte)
    {
      var trytesString = tryte.Message.ToString();
      var firstBreakIndex = trytesString.IndexOf(ChiotaConstants.FirstBreak, StringComparison.Ordinal);
      var secondBreakIndex = trytesString.IndexOf(ChiotaConstants.SecondBreak, StringComparison.Ordinal);

      var dateTrytes = new TryteString(
        trytesString.Substring(
          secondBreakIndex + ChiotaConstants.SecondBreak.Length,
          trytesString.Length - secondBreakIndex - ChiotaConstants.SecondBreak.Length - 1));
      var firstPart = trytesString[trytesString.Length - 1] == 'A';
      var date = DateTime.Parse(dateTrytes.ToUtf8String(), CultureInfo.InvariantCulture);
      var signature = trytesString.Substring(firstBreakIndex + ChiotaConstants.FirstBreak.Length, 30);
      var messageTrytes = trytesString.Substring(0, firstBreakIndex);
      return new ChatMessage { Message = messageTrytes, Date = date, Signature = signature, IsFirstPart = firstPart };
    }

    private static bool TwoPartsOfMessage(List<ChatMessage> sortedEncryptedMessages, int i)
    {
      return sortedEncryptedMessages[i].IsFirstPart != sortedEncryptedMessages[i + 1].IsFirstPart;
    }

    private static List<Contact> RemoveDuplicateContacts(List<Contact> contactList)
    {
      var index = 0;
      while (index < contactList.Count - 1)
      {
        if (contactList[index].ContactAddress == contactList[index + 1].ContactAddress)
        {
          contactList.RemoveAt(index);
        }
        else
        {
          index++;
        }
      }

      return contactList;
    }
  }
}