namespace Chiota.IOTAServices
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services;

  using Newtonsoft.Json;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Mam.Services;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class UserDataOnTangle
  {
    private readonly NtruKex ntru;

    private readonly User user;

    private IAsymmetricKey privateKey;

    public UserDataOnTangle(User user)
    {
      this.ntru = new NtruKex();
      this.user = user;
    }

    public async Task<User> UpdateUserWithOwnDataAddress()
    {
      var ownDataWrappers = await this.user.TangleMessenger.GetMessagesAsync(this.user.OwnDataAdress, 3);
      if (ownDataWrappers != null && ownDataWrappers.Count > 0)
      {
        var decryptedString = new CurlMask().Unmask(ownDataWrappers[0].Message, this.user.Seed).ToUtf8String();
        var decryptedUser = JsonConvert.DeserializeObject<OwnDataUser>(decryptedString);
        this.privateKey = new NTRUPrivateKey(new TryteString(decryptedUser.PrivateKey).ToBytes());
        this.user.Name = decryptedUser.Name;
        this.user.ImageUrl = decryptedUser.ImageUrl;
      }

      return this.user;
    }

    public async Task<User> UpdateUserWithPublicKeyAddress()
    {
      var trytes = await this.user.TangleMessenger.GetMessagesAsync(this.user.PublicKeyAddress, 3);
      var contacts = IotaHelper.GetPublicKeysAndContactAddresses(trytes);

      // more than one key at this address
      if (contacts.Count > 1)
      {
        contacts = this.FindCorrectPublicKey(contacts);

        // generate a new public key address based on changed seed until you find a unused address 
        // this way the attacker doesn't know the next public key address
        List<Contact> newContacts;
        var addresses = new List<Address> { new Address(contacts[0].ContactAdress) };
        do
        {
          var newSeed = this.user.Seed.ToString().Substring(0, 75) + addresses[0].ToString().Substring(0, 6);
          addresses = await Task.Factory.StartNew(() => new AddressGenerator(new Seed(newSeed), SecurityLevel.Low).GetAddresses(0, 1));
          var testtrytes = await this.user.TangleMessenger.GetMessagesAsync(addresses[0].ToString(), 3);
          newContacts = IotaHelper.GetPublicKeysAndContactAddresses(testtrytes);

          if (newContacts == null)
          {
            var requestAdressTrytes = new TryteString(contacts[0].PublicNtruKey + ChiotaIdentifier.LineBreak + this.user.RequestAddress + ChiotaIdentifier.End);
            await this.user.TangleMessenger.SendMessageAsync(requestAdressTrytes, addresses[0].ToString());
          }

          this.user.PublicKeyAddress = addresses[0].ToString();
        }
        while (newContacts?.Count > 1);
      }

      this.user.NtruKeyPair = new NTRUKeyPair(contacts[0].PublicNtruKey, this.privateKey);
      return this.user;
    }

    private List<Contact> FindCorrectPublicKey(List<Contact> contacts)
    {
      const string TestString = "Hello World";
      foreach (var contact in contacts)
      {
        var keypair = new NTRUKeyPair(contact.PublicNtruKey, this.privateKey);
        var encrypt = this.ntru.Encrypt(contact.PublicNtruKey, TestString);
        if (TestString == this.ntru.Decrypt(keypair, encrypt))
        {
          // Removes all infos except the correct version
          contacts.Clear();
          contacts.Add(contact);
          break;
        }
      }

      return contacts;
    }
  }
}
