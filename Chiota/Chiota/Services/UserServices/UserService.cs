namespace Chiota.Services.UserServices
{
  using System.Threading.Tasks;

  using Chiota.Models;

  using Tangle.Net.Entity;

  using Xamarin.Forms;

  /// <summary>
  /// The user service.
  /// </summary>
  public class UserService
  { 
    public UserService(IUserFactory userFactory)
    {
      this.UserFactory = userFactory;
    }

    /// <summary>
    /// Gets the current.
    /// </summary>
    public static User CurrentUser { get; private set; }

    private IUserFactory UserFactory { get; }

    /// <summary>
    /// The set current user.
    /// </summary>
    /// <param name="user">
    /// The user.
    /// </param>
    public static void SetCurrentUser(User user)
    {
      CurrentUser = user;
    }

    /// <summary>
    /// The get current as.
    /// </summary>
    /// <typeparam name="T">
    /// The derived user type.
    /// </typeparam>
    /// <returns>
    /// The <see cref="T"/>.
    /// </returns>
    public static T GetCurrentUserAs<T>() where T : User
    {
      return CurrentUser as T;
    }

    public async Task CreateNew(UserCreationProperties properties)
    {
      var user = await this.UserFactory.CreateAsync(properties.Seed, properties.Name);

      //Application.Current.Properties[ChiotaConstants.SettingsImageKey + user.PublicKeyAddress] = "QmSZQmqVyaQmuHWnPK8hiDaifTY66KPJ7XcBNHBJvsfLEM"; // Default image
      //Application.Current.Properties[ChiotaConstants.SettingsNameKey + user.PublicKeyAddress] = user.Name;
      //Application.Current.Properties[ChiotaConstants.SettingsPowKey] = true;
      //Application.Current.Properties[ChiotaConstants.SettingsNodeKey] = "https://field.deviota.com:443";
      //await Application.Current.SavePropertiesAsync();

      await PublishUserInformation(user);
      SecureStorage.StoreUser(user, properties.Password);

      SetCurrentUser(user);
    }

    private static async Task PublishUserInformation(User user)
    {
      var publicKeyTrytes = user.NtruKeyPair.PublicKey.ToBytes().EncodeBytesAsString();
      var requestAddressTrytes = new TryteString(publicKeyTrytes + ChiotaConstants.LineBreak + user.RequestAddress + ChiotaConstants.End);
      await user.TangleMessenger.SendMessageAsync(requestAddressTrytes, user.PublicKeyAddress);
    }
  }
}