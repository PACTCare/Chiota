namespace Chiota.Services.Storage
{
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services.IOTAServices;

  using Plugin.SecureStorage;

  using Tangle.Net.Entity;

  using Xamarin.Forms;

  public class SecureStorage
  {
    private const string SeedKey = "Seed";

    private const string RequestAddressKey = "RequestAddress";

    private const string PublicKeyAddressKey = "approvedAdressKey";

    public bool CheckUserStored()
    {
      return CrossSecureStorage.Current.HasKey(SeedKey) && CrossSecureStorage.Current.HasKey(RequestAddressKey);
    }

    public async Task<User> GetUser()
    {
      var storedSeed = new Seed(CrossSecureStorage.Current.GetValue(SeedKey));
      var user = new User()
      {
        Seed = storedSeed,
        RequestAddress = CrossSecureStorage.Current.GetValue(RequestAddressKey),
        PublicKeyAddress = CrossSecureStorage.Current.GetValue(PublicKeyAddressKey),
        TangleMessenger = new TangleMessenger(storedSeed),
      };

      user.NtruKeyPair = new NtruKex(true).CreateAsymmetricKeyPair(user.Seed.ToString().ToLower(), user.PublicKeyAddress);
      user.ImageUrl = Application.Current.Properties[ChiotaConstants.SettingsImageKey + user.PublicKeyAddress] as string;
      user.Name = Application.Current.Properties[ChiotaConstants.SettingsNameKey + user.PublicKeyAddress] as string;

      try
      {
        return await new UserDataOnTangle(user).UniquePublicKey();
      }
      catch
      {
        // incomplete => setup interrupted or not yet finished
        return null;
      }
    }

    public bool StoreUser(User user)
    {
      if (user.StoreSeed)
      {
        try
        {
          CrossSecureStorage.Current.SetValue(SeedKey, user.Seed.Value);
          CrossSecureStorage.Current.SetValue(RequestAddressKey, user.RequestAddress);
          CrossSecureStorage.Current.SetValue(PublicKeyAddressKey, user.PublicKeyAddress);
          return true;
        }
        catch
        {
          return false;
        }
      }

      return true;
    }

    public void DeleteUser()
    {
      CrossSecureStorage.Current.DeleteKey(SeedKey);
      CrossSecureStorage.Current.DeleteKey(RequestAddressKey);
      CrossSecureStorage.Current.DeleteKey(PublicKeyAddressKey);
    }
  }
}