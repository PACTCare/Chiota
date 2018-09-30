namespace Chiota.Services.Iota
{
  using System.Collections.Generic;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;
  using Chiota.Models;
  using Chiota.Services.DependencyInjection;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  /// <summary>
  /// The iota helper.
  /// </summary>
  public static class IotaHelper
  {
    public static async Task<string> GetChatPasSalt(User user, string chatKeyAddress)
    {
      var messages = await DependencyResolver.Resolve<IMessenger>().GetMessagesByAddressAsync(new Address(chatKeyAddress), new MessageBundleParser());
      var chatPasSalt = new List<string>();
      foreach (var message in messages)
      {
        try
        {
          var pasSalt = Encoding.UTF8.GetString(NtruEncryption.Key.Decrypt(user.NtruKeyPair, message.Payload.DecodeBytesFromTryteString()));
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
  }
}