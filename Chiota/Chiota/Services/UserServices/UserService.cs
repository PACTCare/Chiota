namespace Chiota.Services.UserServices
{
  using Chiota.Models;

  /// <summary>
  /// The user service.
  /// </summary>
  public static class UserService
  {
    /// <summary>
    /// Gets the current.
    /// </summary>
    public static User CurrentUser { get; private set; }

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
  }
}