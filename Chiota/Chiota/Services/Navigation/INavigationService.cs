namespace Chiota.Services.Navigation
{
  using Xamarin.Forms;

  /// <summary>
  /// The NavigationService interface.
  /// </summary>
  public interface INavigationService
  {
    /// <summary>
    /// Gets the logged in entry point.
    /// </summary>
    Page LoggedInEntryPoint { get; }

    /// <summary>
    /// Gets the logged out entry point.
    /// </summary>
    Page LoginEntryPoint { get; }
  }
}