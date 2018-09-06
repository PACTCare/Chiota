namespace Chiota.Services.UserServices
{
  using System.Threading.Tasks;

  using Chiota.Exceptions;
  using Chiota.Models;
  using Chiota.Services.Iota;

  using Newtonsoft.Json;

  using Plugin.SecureStorage;

  using Tangle.Net.Entity;

  using Xamarin.Forms;

  public static class SecureStorage
  {
    private const string PasswordHash = "PasswordHash";
    private const string EncryptionSalt = "EncryptionSalt";
    private const string CurrentUser = "CurrentUser";

    public static bool IsUserStored =>
      CrossSecureStorage.Current.HasKey(PasswordHash) && CrossSecureStorage.Current.HasKey(CurrentUser)
                                                      && CrossSecureStorage.Current.HasKey(EncryptionSalt);

    public static async Task<User> GetUser()
    {
      var user = UserService.CurrentUser;

      // old version check
      if (!Application.Current.Properties.ContainsKey(ChiotaConstants.SettingsImageKey + user.PublicKeyAddress))
      {
        return null;
      }

      user.NtruKeyPair = new NtruKex(true).CreateAsymmetricKeyPair(user.Seed.ToLower(), user.PublicKeyAddress);

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

    public static async Task LoginUser(string password)
    {
      var passwordHash = UserDataEncryption.Hash(password);
      if (passwordHash != CrossSecureStorage.Current.GetValue(PasswordHash))
      {
        throw new InvalidUserInputException(new ExcInfo(), Details.AuthInvalidUserInputPassword);
      }

      var encryptionSalt = CrossSecureStorage.Current.GetValue(EncryptionSalt);
      var encryptedUser = CrossSecureStorage.Current.GetValue(CurrentUser);

      var decryptedUser = JsonConvert.DeserializeObject<User>(UserDataEncryption.Decrypt(encryptedUser, password, encryptionSalt));

      decryptedUser.TangleMessenger = new TangleMessenger(new Seed(decryptedUser.Seed));
      UserService.SetCurrentUser(decryptedUser);

      await GetUser();
    }

    public static void StoreUser(User user, string password)
    {
      if (!user.StoreSeed)
      {
        return;
      }

      var passwordHash = UserDataEncryption.Hash(password);
      var encryptionSalt = Seed.Random().Value;

      CrossSecureStorage.Current.SetValue(PasswordHash, passwordHash);
      CrossSecureStorage.Current.SetValue(EncryptionSalt, encryptionSalt);

      var serializedUser = JsonConvert.SerializeObject(user);
      var encryptedUser = UserDataEncryption.Encrypt(serializedUser, password, encryptionSalt);

      CrossSecureStorage.Current.SetValue(CurrentUser, encryptedUser);
    }

    public static void DeleteUser()
    {
      CrossSecureStorage.Current.DeleteKey(PasswordHash);
      CrossSecureStorage.Current.DeleteKey(EncryptionSalt);
      CrossSecureStorage.Current.DeleteKey(CurrentUser);
    }
  }
}