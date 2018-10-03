namespace Chiota.Services.UserServices
{
  using System.Diagnostics.CodeAnalysis;
  using System.Threading.Tasks;

  using Chiota.Exceptions;
  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.CheckUser;
  using Chiota.Models;
  using Chiota.Services.DependencyInjection;

  using Newtonsoft.Json;

  using Plugin.SecureStorage;

  using Tangle.Net.Entity;

  [ExcludeFromCodeCoverage]
  public static class SecureStorage
  {
    private const string PasswordHash = "PasswordHash";
    private const string EncryptionSalt = "EncryptionSalt";
    private const string CurrentUser = "CurrentUser";

    public static bool IsUserStored =>
      CrossSecureStorage.Current.HasKey(PasswordHash) && CrossSecureStorage.Current.HasKey(CurrentUser)
                                                      && CrossSecureStorage.Current.HasKey(EncryptionSalt);

    public static async Task LoginUser(string password)
    {
      ValidatePassword(password);

      var encryptionSalt = CrossSecureStorage.Current.GetValue(EncryptionSalt);
      var encryptedUser = CrossSecureStorage.Current.GetValue(CurrentUser);

      var decryptedUser = JsonConvert.DeserializeObject<User>(UserDataEncryption.Decrypt(encryptedUser, password, encryptionSalt));
      decryptedUser.NtruKeyPair = NtruEncryption.Key.CreateAsymmetricKeyPair(decryptedUser.Seed.ToLower(), decryptedUser.PublicKeyAddress);

      var checkUserResponse = await DependencyResolver.Resolve<IUsecaseInteractor<CheckUserRequest, CheckUserResponse>>().ExecuteAsync(
                                new CheckUserRequest
                                  {
                                    PublicKey = decryptedUser.NtruKeyPair.PublicKey,
                                    PublicKeyAddress = new Address(decryptedUser.PublicKeyAddress),
                                    RequestAddress = new Address(decryptedUser.RequestAddress),
                                    Seed = new Seed(decryptedUser.Seed)
                                  });

      if (checkUserResponse.Code == ResponseCode.NewPublicKeyAddress)
      {
        decryptedUser.PublicKeyAddress = checkUserResponse.PublicKeyAddress.Value;
      }

      UserService.SetCurrentUser(decryptedUser);
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

    public static void UpdateUser(string password)
    {
      ValidatePassword(password);

      var encryptionSalt = CrossSecureStorage.Current.GetValue(EncryptionSalt);
      var serializedUser = JsonConvert.SerializeObject(UserService.CurrentUser);
      var encryptedUser = UserDataEncryption.Encrypt(serializedUser, password, encryptionSalt);

      CrossSecureStorage.Current.SetValue(CurrentUser, encryptedUser);
    }

    public static void ValidatePassword(string password)
    {
      var passwordHash = UserDataEncryption.Hash(password);
      if (passwordHash != CrossSecureStorage.Current.GetValue(PasswordHash))
      {
        throw new InvalidUserInputException(new ExcInfo(), Details.AuthInvalidUserInputPassword);
      }
    }

    public static void DeleteUser()
    {
      CrossSecureStorage.Current.DeleteKey(PasswordHash);
      CrossSecureStorage.Current.DeleteKey(EncryptionSalt);
      CrossSecureStorage.Current.DeleteKey(CurrentUser);
    }
  }
}