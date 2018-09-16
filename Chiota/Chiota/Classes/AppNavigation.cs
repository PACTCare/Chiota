using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views.Messenger;
using Xamarin.Forms;

namespace Chiota.Classes
{
  using Chiota.Views.Authentication;

  public static class AppNavigation
    {
        #region Attributes

        private static NavigationImplementation navigation;

        #endregion

        #region Properties

        public static NavigationImplementation NavigationInstance => navigation ?? (navigation = new NavigationImplementation());

        #endregion

        #region Methods

        #region ShowStartUp

        public static void ShowStartUp()
        {
            NavigationPage container;

            // ReSharper disable once ConvertIfStatementToConditionalTernaryExpression
            if (SecureStorage.IsUserStored)
            {
                // User is logged in.
                container = SetNavigationStyles(new NavigationPage(new LogInView()));
            }
            else
            {
                // Database is empty or no user is logged in.
                container = SetNavigationStyles(new NavigationPage(new WelcomeView()));
            }

            // Show the page.
            Application.Current.MainPage = container;
        }

        #endregion

        #region ShowMessenger

        public static void ShowMessenger()
        {
            // Show the page.
            var container = SetNavigationStyles(new NavigationPage(new MessengerTabbedView()));
            Application.Current.MainPage = container;
        }

        #endregion

        #region SetNavigationStyles

        private static NavigationPage SetNavigationStyles(NavigationPage page)
        {
            page.BarBackgroundColor = (Color)Application.Current.Resources["AccentColor"];
            page.BarTextColor = (Color)Application.Current.Resources["NavigationBarTextColor"];

            return page;
        }

        #endregion

        #endregion
    }
}