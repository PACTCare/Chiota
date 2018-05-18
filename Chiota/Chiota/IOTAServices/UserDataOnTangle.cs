namespace Chiota.IOTAServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services;

  using Newtonsoft.Json;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Curl;
  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;

  public class UserDataOnTangle
  {
    private readonly User user;

    public UserDataOnTangle(User user)
    {
      this.user = user;
    }

    public async Task<User> UpdateUserWithOwnDataAddress()
    {
      var trytes = await this.user.TangleMessenger.GetMessagesAsync(this.user.OwnDataAdress, 3);
      foreach (var tryte in trytes)
      {
        try
        {
          var decrypted = new NtruKex().Decrypt(this.user.NtruContactPair, tryte.Message.DecodeBytesFromTryteString());

          var decryptedUser = JsonConvert.DeserializeObject<OwnDataUser>(decrypted);
          this.user.Name = decryptedUser.Name;
          this.user.ImageUrl = ChiotaConstants.ImagePath + decryptedUser.ImageUrl;
        }
        catch
        {
          // ignored
        }
      }

      return this.user;
    }

    public async Task<User> UniquePublicKey()
    {
      var trytes = await this.user.TangleMessenger.GetMessagesAsync(this.user.PublicKeyAddress, 3);
      var contacts = IotaHelper.GetPublicKeysAndContactAddresses(trytes);

      // more than one key at this address or something is wrong with the key
      if (contacts.Count > 1 || contacts.Count == 0)
      {
        // generate a new public key address based on a changed seed until you find an unused address 
        // this way the attacker doesn't know the next public key address
        List<Contact> newContacts;
        var addresses = new List<Address> { new Address(this.user.PublicKeyAddress) };
        do
        {
          var newSeed = this.user.Seed.ToString().Substring(0, 75) + addresses[0].ToString().Substring(0, 6);
          var addressGenerator = new AddressGenerator(new Kerl(), new KeyGenerator(new Kerl(), new IssSigningHelper()));
          addresses = await Task.Factory.StartNew(() => addressGenerator.GetAddresses(new Seed(newSeed), SecurityLevel.Medium, 0, 1));

          var testtrytes = await this.user.TangleMessenger.GetMessagesAsync(addresses[0].ToString(), 3);

          // returns also null if something wrong with ntru key pair
          newContacts = IotaHelper.GetPublicKeysAndContactAddresses(testtrytes);

          if (newContacts == null || newContacts.Count == 0)
          {
            var requestAdressTrytes = new TryteString(this.user.NtruChatPair.PublicKey.ToBytes().EncodeBytesAsString() + ChiotaConstants.LineBreak + this.user.RequestAddress + ChiotaConstants.End);
            await this.user.TangleMessenger.SendMessageAsync(requestAdressTrytes, addresses[0].ToString());
          }

          this.user.PublicKeyAddress = addresses[0].ToString();
        }
        while (newContacts?.Count > 1);
      }

      return this.user;
    }
  }
}
