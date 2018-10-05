using System.Threading.Tasks;
using Chiota.Services.Database;
using Chiota.ViewModels.Base;
using Chiota.Views.Authentication;
using Chiota.Views.Messenger;
using Xamarin.Essentials;
using Xamarin.Forms;

namespace Chiota.Base
{
    public static class AppBase
    {
        #region Attributes

        private static NavigationImplementation navigation;

        #endregion

        #region Properties

        public static NavigationImplementation NavigationInstance => navigation ?? (navigation = new NavigationImplementation());

        #endregion

        #region Methods

        #region ShowStartUp

        public static async Task ShowStartUpAsync()
        {
            NavigationPage container;

            var isUserStored = await DatabaseService.DatabaseInfo.IsUserStoredAsync();
            if (isUserStored)
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
            page.BarBackgroundColor = (Color)Application.Current.Resources["AccentDarkColor"];
            page.BarTextColor = (Color)Application.Current.Resources["BrightTextColor"];

            return page;
        }

        #endregion

        #endregion
    }
}