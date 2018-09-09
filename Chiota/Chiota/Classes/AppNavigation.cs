using Chiota.Pages.Authentication;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;

using Xamarin.Forms;

namespace Chiota.Classes
{
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