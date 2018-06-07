namespace Chiota.Services.Navigation
{
  using Chiota.Views;

  using Xamarin.Forms;

  /// <summary>
  /// The default navigation service.
  /// </summary>
  public class DefaultNavigationService : INavigationService
  {
    /// <inheritdoc />
    public Page LoggedInEntryPoint => new ContactPage();
  }
}