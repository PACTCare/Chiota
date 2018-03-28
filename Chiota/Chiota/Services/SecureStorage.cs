namespace Chiota.Services
{
  using Chiota.IOTAServices;
  using Chiota.Models;

  using Plugin.SecureStorage;

  using Tangle.Net.Entity;

  public class SecureStorage
  {
    private const string SeedKey = "Seed";

    private const string OwnDataAdressKey = "OwnDataAdress";

    private const string RequestAddressKey = "RequestAddress";

    private const string ApprovedAddressKey = "ApprovedAddress";

    private const string PublicKeyAddressKey = "approvedAdressKey";

    public bool CheckUserStored()
    {
      return CrossSecureStorage.Current.HasKey(SeedKey) &&
             CrossSecureStorage.Current.HasKey(OwnDataAdressKey) &&
             CrossSecureStorage.Current.HasKey(RequestAddressKey) &&
             CrossSecureStorage.Current.HasKey(ApprovedAddressKey) &&
             CrossSecureStorage.Current.HasKey(PublicKeyAddressKey);
    }

    public User GetUser()
    {
      var storedSeed = new Seed(CrossSecureStorage.Current.GetValue(SeedKey));
      var user = new User()
      {
        Seed = storedSeed,
        OwnDataAdress = CrossSecureStorage.Current.GetValue(OwnDataAdressKey),
        RequestAddress = CrossSecureStorage.Current.GetValue(RequestAddressKey),
        ApprovedAddress = CrossSecureStorage.Current.GetValue(ApprovedAddressKey),
        PublicKeyAddress = CrossSecureStorage.Current.GetValue(PublicKeyAddressKey),
        TangleMessenger = new TangleMessengerFactory().Create(storedSeed)
      };

      var ownDataWrappers = user.TangleMessenger.GetMessages(user.OwnDataAdress);
      user = IotaHelper.UpdateUserWithTangleInfos(user, ownDataWrappers);
      return user;
    }

    public bool StoreUser(User user)
    {
      try
      {
        CrossSecureStorage.Current.SetValue(SeedKey, user.Seed.Value);
        CrossSecureStorage.Current.SetValue(OwnDataAdressKey, user.OwnDataAdress);
        CrossSecureStorage.Current.SetValue(RequestAddressKey, user.RequestAddress);
        CrossSecureStorage.Current.SetValue(ApprovedAddressKey, user.ApprovedAddress);
        CrossSecureStorage.Current.SetValue(PublicKeyAddressKey, user.PublicKeyAddress);
        return true;
      }
      catch
      {
        return false;
      }
    }

    public void DeleteUser()
    {
      CrossSecureStorage.Current.DeleteKey(SeedKey);
      CrossSecureStorage.Current.DeleteKey(OwnDataAdressKey);
      CrossSecureStorage.Current.DeleteKey(RequestAddressKey);
      CrossSecureStorage.Current.DeleteKey(PublicKeyAddressKey);
      CrossSecureStorage.Current.DeleteKey(PublicKeyAddressKey);
    }
  }
}