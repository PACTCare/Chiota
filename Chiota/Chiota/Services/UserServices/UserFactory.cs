namespace Chiota.Services.UserServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services.Iota;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;

  using Xamarin.Forms;

  /// <inheritdoc />
  public class UserFactory : IUserFactory
  {
    /// <inheritdoc />
    public async Task<User> CreateAsync(Seed seed, bool storeSeed)
    {
      var addresses = await GenerateChiotaAddresses(seed);
      
      // First time set default values
      if (!Application.Current.Properties.ContainsKey(ChiotaConstants.SettingsImageKey + addresses[0].Value))
      {
        Application.Current.Properties[ChiotaConstants.SettingsImageKey + addresses[0].Value] = "https://chiota.blob.core.windows.net/userimages/default.png";
        Application.Current.Properties[ChiotaConstants.SettingsNameKey + addresses[0].Value] = string.Empty;
        Application.Current.Properties[ChiotaConstants.SettingsPowKey] = true;
        Application.Current.Properties[ChiotaConstants.SettingsNodeKey] = "https://field.carriota.com:443";
        await Application.Current.SavePropertiesAsync();
      }

      return new User
               {
                 Name = null,
                 Seed = seed,
                 ImageUrl = null,
                 StoreSeed = storeSeed,
                 PublicKeyAddress = addresses[0].Value, // + addresses[1].WithChecksum().Checksum.Value,
                 RequestAddress = addresses[1].Value,
                 TangleMessenger = new TangleMessenger(seed),
                 NtruKeyPair = new NtruKex(true).CreateAsymmetricKeyPair(seed.ToString().ToLower(), addresses[0].Value) 
               };
    }

    private static async Task<List<Address>> GenerateChiotaAddresses(Seed seed)
    {
      // addresses can be generated based on each other to make it faster
      var addresses = await Task.Run(() => new AddressGenerator().GetAddresses(seed, SecurityLevel.Medium, 0, 1));
      addresses.Add(Helper.GenerateAddress(addresses[0]));
      return addresses;
    }
  }
}
