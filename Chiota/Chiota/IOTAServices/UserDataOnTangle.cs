namespace Chiota.IOTAServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Models;

  using Newtonsoft.Json;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Curl;
  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  public class UserDataOnTangle
  {
    private readonly User user;

    public UserDataOnTangle(User user)
    {
      this.user = user;
    }

    public async Task<User> UpdateUserWithOwnDataAddress()
    {
      var ownDataWrappers = await this.user.TangleMessenger.GetMessagesAsync(this.user.OwnDataAdress, 3);
      if (ownDataWrappers != null && ownDataWrappers.Count > 0)
      {
        var decryptedUser = JsonConvert.DeserializeObject<OwnDataUser>(ownDataWrappers[0].Message.ToUtf8String());
        this.user.Name = decryptedUser.Name;
        this.user.ImageUrl = decryptedUser.ImageUrl;
      }

      return this.user;
    }

    public async Task<User> UniquePublicKey()
    {
      var trytes = await this.user.TangleMessenger.GetMessagesAsync(this.user.PublicKeyAddress, 3);
      var contacts = IotaHelper.GetPublicKeysAndContactAddresses(trytes);

      // more than one key at this address
      if (contacts.Count > 1)
      {
        // generate a new public key address based on a changed seed until you find an unused address 
        // this way the attacker doesn't know the next public key address
        List<Contact> newContacts;
        var addresses = new List<Address> { new Address(contacts[0].ContactAdress) };
        do
        {
          var newSeed = this.user.Seed.ToString().Substring(0, 75) + addresses[0].ToString().Substring(0, 6);
          var addressGenerator = new AddressGenerator(new Kerl(), new KeyGenerator(new Kerl(), new IssSigningHelper()));
          addresses = await Task.Factory.StartNew(() => addressGenerator.GetAddresses(new Seed(newSeed), SecurityLevel.Medium, 0, 1));

          var testtrytes = await this.user.TangleMessenger.GetMessagesAsync(addresses[0].ToString(), 3);
          newContacts = IotaHelper.GetPublicKeysAndContactAddresses(testtrytes);

          if (newContacts == null || newContacts.Count == 0)
          {
            var requestAdressTrytes = new TryteString(this.user.NtruChatPair.PublicKey.ToBytes().ToTrytes() + ChiotaIdentifier.LineBreak + this.user.RequestAddress + ChiotaIdentifier.End);
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
