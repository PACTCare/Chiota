namespace Chiota.Messenger.Entity
{
  using System;
  using System.Text;

  using Chiota.Messenger.Encryption;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class ContactExchange
  {
    private ContactExchange()
    {
    }

    public TryteString Payload { get; private set; }

    public static ContactExchange Create(Contact contactDetails, IAsymmetricKey receiverPublicKey, IAsymmetricKey userPublicKey)
    {
      var encryption = NtruEncryption.Key;

      var encryptedContactDetails = encryption.Encrypt(receiverPublicKey, Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(contactDetails)));
      var nonce = encryption.Encrypt(userPublicKey, Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("O")));

      return new ContactExchange
               {
                 Payload = TryteString.FromBytes(encryptedContactDetails).Concat(Constants.LineBreak).Concat(TryteString.FromBytes(nonce))
               };
    }
  }
}