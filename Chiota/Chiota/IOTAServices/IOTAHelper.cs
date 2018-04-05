namespace Chiota.IOTAServices
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;
  using Tangle.Net.Mam.Services;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class IotaHelper
  {
    public static bool CorrectSeedAdressChecker(string seed)
    {
      if (seed == null)
      {
        return false;
      }

      return seed != string.Empty && seed.All(c => "ABCDEFGHIJKLMNOPQRSTUVWXYZ9".Contains(c));
    }

    public static Contact FilterRequestInfos(IEnumerable<TryteString> trytes)
    {
      var contact = new Contact();
      var oneKeyAlreadyFound = false;
      foreach (var tryte in trytes)
      {
        var trytesString = tryte.ToString();
        if (!trytesString.Contains("9CHIOTAYOURIOTACHATAPP9"))
        {
          continue;
        }

        if (oneKeyAlreadyFound)
        {
          return null;
        }

        var index = trytesString.IndexOf("9CHIOTAYOURIOTACHATAPP9", StringComparison.Ordinal);
        var publicKeyString = trytesString.Substring(0, index);
        var bytesKey = new TryteString(publicKeyString).ToBytes();

        contact.PublicNtruKey = new NTRUPublicKey(bytesKey);

        contact.ContactAdress = trytesString.Substring(index + 23, 81);
        oneKeyAlreadyFound = true;
      }

      return contact;
    }

    public static List<ChatMessage> FilterChatMessages(IEnumerable<TryteString> trytes, NtruKex ntruKex, IAsymmetricKeyPair keyPair, DateTime lastPostDate)
    {
      var chatMessages = new List<ChatMessage>();
      foreach (var tryte in trytes)
      {
        try
        {
          var trytesString = tryte.ToString();
          var firstBreak = trytesString.IndexOf("9CHIOTAYOUR9", StringComparison.Ordinal);
          var secondBreak = trytesString.IndexOf("9IOTACHATAPP9", StringComparison.Ordinal);
          var dateTrytes = new TryteString(trytesString.Substring(secondBreak + 13, trytesString.Length - secondBreak - 13));
          var date = DateTime.Parse(dateTrytes.ToUtf8String());

          // decrypt only if this is a new message
          if (date > lastPostDate)
          {
            var signature = trytesString.Substring(firstBreak + 12, 30);
            var messageTrytes = new TryteString(trytesString.Substring(0, firstBreak));
            var decryptedMessage = ntruKex.Decrypt(keyPair, messageTrytes.ToBytes());
            var chatMessage = new ChatMessage { Message = decryptedMessage, Date = date, Signature = signature };
            chatMessages.Add(chatMessage);
          }
        }
        catch
        {
          // ignored
        }
      }

      return chatMessages;
    }

    public static async Task<User> UpdateUserWithTangleInfos(User user, List<TryteString> ownDataWrappers)
    {
      var trytes = await user.TangleMessenger.GetMessagesAsync(user.PublicKeyAddress, 3);
      var contact = FilterRequestInfos(trytes);
      var decrypted = new CurlMask().Unmask(ownDataWrappers[0], user.Seed);
      var decryptedString = decrypted.ToUtf8String();
      var decryptedUser = JsonConvert.DeserializeObject<OwnDataUser>(decryptedString);
      user.Name = decryptedUser.Name;
      user.ImageUrl = decryptedUser.ImageUrl;
      IAsymmetricKey privateKey = new NTRUPrivateKey(new TryteString(decryptedUser.PrivateKey).ToBytes());
      user.NtruKeyPair = new NTRUKeyPair(contact.PublicNtruKey, privateKey);
      return user;
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
  }
}
