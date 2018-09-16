namespace Chiota.Services.Iota
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
  using Chiota.Models;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.ViewModels;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The iota helper.
  /// </summary>
  public static class IotaHelper
  {
    public static async Task<List<MessageViewModel>> GetNewMessages(IAsymmetricKeyPair keyPair, Contact contact)
    {
      var messages = await DependencyResolver.Resolve<IMessenger>()
                       .GetMessagesByAddressAsync(new Address(contact.ChatAddress), new MessageBundleParser());
      var messagesEncrypted = new List<ChatMessage>();
      foreach (var message in messages)
      {
        try
        {
          messagesEncrypted.Add(ReadChatMessage(message));
        }
        catch
        {
          // ignored
        }
      }

      var sortedEncryptedMessages = messagesEncrypted.OrderBy(o => o.Date).ToList();
      var messageViewModels = new List<MessageViewModel>();

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
          messageViewModels.Add(new MessageViewModel
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

      return messageViewModels;
    }

    public static async Task<List<Contact>> GetPublicKeysAndContactAddresses(string receiverAddress)
    {
      var messages = await DependencyResolver.Resolve<IMessenger>()
                       .GetMessagesByAddressAsync(new Address(receiverAddress), new MessageBundleParser());
      var contacts = new List<Contact>();
      foreach (var message in messages)
      {
        var trytesString = message.Payload.Value;
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
      var messages = await DependencyResolver.Resolve<IMessenger>()
                       .GetMessagesByAddressAsync(new Address(chatKeyAddress), new MessageBundleParser());
      var chatPasSalt = new List<string>();
      foreach (var message in messages)
      {
        try
        {
          var pasSalt = Encoding.UTF8.GetString(
            new NtruKex(true).Decrypt(user.NtruKeyPair, message.Payload.DecodeBytesFromTryteString()));
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

    private static ChatMessage ReadChatMessage(Message message)
    {
      var trytesString = message.Payload.Value;
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