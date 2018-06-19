namespace Chiota.IOTAServices
{
  using System.Collections.Generic;
  using System.Text;
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
      // This will return information even after a snapshot, because it's stored local
      var trytes = await this.user.TangleMessenger.GetMessagesAsync(this.user.OwnDataAdress, 3);
      foreach (var tryte in trytes)
      {
        var decryptedPrivateData = new NtruKex(true).Decrypt(this.user.NtruKeyPair, tryte.Message.DecodeBytesFromTryteString());

        if (decryptedPrivateData != null)
        {
          var decryptedUser = JsonConvert.DeserializeObject<OwnDataUser>(Encoding.UTF8.GetString(decryptedPrivateData));
          this.user.Name = decryptedUser.Name;
          this.user.ImageUrl = ChiotaConstants.ImagePath + decryptedUser.ImageUrl;
        }
      }

      return this.user;
    }

    public async Task<User> UniquePublicKey()
    {
      // load from tangle not from SQLlit
      var contacts = await IotaHelper.GetPublicKeysAndContactAddresses(this.user.TangleMessenger, this.user.PublicKeyAddress, true);
      var requestAdressTrytes = new TryteString(this.user.NtruKeyPair.PublicKey.ToBytes().EncodeBytesAsString() + ChiotaConstants.LineBreak + this.user.RequestAddress + ChiotaConstants.End);

      // after a snapshot, upload public key again
      if (contacts.Count == 0)
      {
        await this.user.TangleMessenger.SendMessageAsync(requestAdressTrytes, this.user.PublicKeyAddress);
      }
      else if (contacts.Count > 1) 
      {
        // more than one key at this address 
        // generate a new public key address based on a changed seed until you find an unused address 
        // this way the attacker doesn't know the next public key address
        List<Contact> newContacts;
        var addresses = new List<Address> { new Address(this.user.PublicKeyAddress) };
        do
        {
          var newSeed = this.user.Seed.ToString().Substring(0, 75) + addresses[0].ToString().Substring(0, 6);
          var addressGenerator = new AddressGenerator(new Kerl(), new KeyGenerator(new Kerl(), new IssSigningHelper()));
          addresses = await Task.Factory.StartNew(() => addressGenerator.GetAddresses(new Seed(newSeed), SecurityLevel.Medium, 0, 1));

          // returns also null if something wrong with ntru key pair
          newContacts = await IotaHelper.GetPublicKeysAndContactAddresses(this.user.TangleMessenger, addresses[0].ToString(), true);

          if (newContacts == null || newContacts.Count == 0)
          {
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
