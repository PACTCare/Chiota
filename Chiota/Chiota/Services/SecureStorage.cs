namespace Chiota.Services
{
  using System.Threading.Tasks;

  using Chiota.IOTAServices;
  using Chiota.Models;

  using Plugin.SecureStorage;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  public class SecureStorage
  {
    private const string SeedKey = "Seed";

    private const string OwnDataAdressKey = "OwnDataAdress";

    private const string RequestAddressKey = "RequestAddress";

    private const string ApprovedAddressKey = "ApprovedAddress";

    private const string PublicKeyAddressKey = "approvedAdressKey";

    private const string ChatPublicKey = "ChatPublicKey";

    private const string ChatPrivateKey = "ChatPrivateKey";

    private const string ContactPublicKey = "ContactPublicKey";

    private const string ContactPrivateKey = "ContactPrivateKey";

    public bool CheckUserStored()
    {
      return CrossSecureStorage.Current.HasKey(SeedKey) &&
             CrossSecureStorage.Current.HasKey(OwnDataAdressKey) &&
             CrossSecureStorage.Current.HasKey(RequestAddressKey) &&
             CrossSecureStorage.Current.HasKey(ApprovedAddressKey) &&
             CrossSecureStorage.Current.HasKey(PublicKeyAddressKey);
    }

    public async Task<User> GetUser()
    {
      var storedSeed = new Seed(CrossSecureStorage.Current.GetValue(SeedKey));
      var user = new User()
      {
        Seed = storedSeed,
        OwnDataAdress = CrossSecureStorage.Current.GetValue(OwnDataAdressKey),
        RequestAddress = CrossSecureStorage.Current.GetValue(RequestAddressKey),
        ApprovedAddress = CrossSecureStorage.Current.GetValue(ApprovedAddressKey),
        PublicKeyAddress = CrossSecureStorage.Current.GetValue(PublicKeyAddressKey),
        TangleMessenger = new TangleMessenger(storedSeed),
      };

      var chatPublicKey = new NTRUPublicKey(new TryteString(CrossSecureStorage.Current.GetValue(ChatPublicKey)).DecodeBytesFromTryteString());
      var chatPrivateKey = new NTRUPrivateKey(new TryteString(CrossSecureStorage.Current.GetValue(ChatPrivateKey)).DecodeBytesFromTryteString());

      var contactPublicKey = new NTRUPublicKey(new TryteString(CrossSecureStorage.Current.GetValue(ContactPublicKey)).DecodeBytesFromTryteString());
      var contactPrivateKey = new NTRUPrivateKey(new TryteString(CrossSecureStorage.Current.GetValue(ContactPrivateKey)).DecodeBytesFromTryteString());

      user.NtruChatPair = new NTRUKeyPair(chatPublicKey, chatPrivateKey);
      user.NtruContactPair = new NTRUKeyPair(contactPublicKey, contactPrivateKey);

      try
      {
        var tangleData = new UserDataOnTangle(user);
        await tangleData.UpdateUserWithOwnDataAddress();
        user = await tangleData.UniquePublicKey();
        return user;
      }
      catch
      {
        // incomplete => setup interrupted or not yet finished
        return null;
      }
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
        CrossSecureStorage.Current.SetValue(ChatPublicKey, user.NtruChatPair.PublicKey.ToBytes().EncodeBytesAsString());
        CrossSecureStorage.Current.SetValue(ChatPrivateKey, user.NtruChatPair.PrivateKey.ToBytes().EncodeBytesAsString());
        CrossSecureStorage.Current.SetValue(ContactPublicKey, user.NtruContactPair.PublicKey.ToBytes().EncodeBytesAsString());
        CrossSecureStorage.Current.SetValue(ContactPrivateKey, user.NtruContactPair.PrivateKey.ToBytes().EncodeBytesAsString());
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
      CrossSecureStorage.Current.DeleteKey(ChatPrivateKey);
      CrossSecureStorage.Current.DeleteKey(ChatPublicKey);
      CrossSecureStorage.Current.DeleteKey(ContactPrivateKey);
      CrossSecureStorage.Current.DeleteKey(ContactPublicKey);
    }
  }
}