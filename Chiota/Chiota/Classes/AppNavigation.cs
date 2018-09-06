namespace Chiota.Classes
{
  using Chiota.Pages.Authentication;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;

  /// <summary>
  /// The app navigation.
  /// </summary>
  public static class AppNavigation
  {
    /// <summary>
    /// The _navigation.
    /// </summary>
    private static NavigationImplementation navigation;

    public static NavigationImplementation NavigationInstance => navigation ?? (navigation = new NavigationImplementation());

    /// <summary>
    /// Generate a new navigation container for the splash page as single page.
    /// </summary>
    public static void ShowStartUp()
    {
      NavigationPage container;

      // ReSharper disable once ConvertIfStatementToConditionalTernaryExpression
      if (SecureStorage.IsUserStored)
      {
        // User is logged in.
        container = SetNavigationStyles(new NavigationPage(new LogInPage()));
      }
      else
      {
        // Database is empty or no user is logged in.
        container = SetNavigationStyles(new NavigationPage(new WelcomePage()));
      }

      // Show the page.
      Application.Current.MainPage = container;
    }

    private static NavigationPage SetNavigationStyles(NavigationPage page)
    {
      page.BarBackgroundColor = (Color)Application.Current.Resources["AccentColor"];
      page.BarTextColor = (Color)Application.Current.Resources["NavigationBarTextColor"];

      return page;
    }
  }
}