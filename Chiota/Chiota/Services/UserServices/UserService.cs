namespace Chiota.Services.UserServices
{
  using System.Threading.Tasks;

  using Chiota.Models;

  using Tangle.Net.Entity;

  /// <summary>
  /// The user service.
  /// </summary>
  public class UserService
  { 
    public UserService(IUserFactory userFactory)
    {
      this.UserFactory = userFactory;
    }

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

      SecureStorage.StoreUser(user, properties.Password);
      SetCurrentUser(user);
    }
  }
}