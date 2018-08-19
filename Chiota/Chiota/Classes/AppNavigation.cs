using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Pages.Authentication;
using Chiota.Services.Storage;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views;
using Xamarin.Forms;

namespace Chiota.Classes
{
    public static class AppNavigation
    {
        #region Attributes

        private static NavigationImplementation _navigation;

        #endregion

        #region Properties

        /// <summary>
        /// Returns single instance for navigation objects.
        /// </summary>
        public static NavigationImplementation NavigationInstance
        {
            get
            {
                if (_navigation == null)
                    _navigation = new NavigationImplementation();

                return _navigation;
            }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Generate a new navigation container for the splash page as single page.
        /// </summary>
        public static void ShowStartUp()
        {
            NavigationPage container = null;

            //If a user is stored in the database,
            //the user will forwarded directly to the contact page,
            //otherwise (the database is empty) the user need to create a new account.
            if (false)
            {
                //User is logged in.
                var navigation = new NavigationPage(new LogInPage());
                container = SetNavigationStyles(navigation);
            }
            else
            {
                //Database is empty or no user is logged in.
                var navigation = new NavigationPage(new WelcomePage());
                container = SetNavigationStyles(navigation);
            }

            //Show the page.
            Application.Current.MainPage = container;
        }

        /// <summary>
        /// Set the navigation styles of the application.
        /// </summary>
        /// <param name="page"></param>
        /// <returns></returns>
        private static NavigationPage SetNavigationStyles(NavigationPage page)
        {
            page.BarBackgroundColor = (Color)Application.Current.Resources["AccentColor"];
            page.BarTextColor = (Color)Application.Current.Resources["NavigationBarTextColor"];

            return page;
        }

        #endregion
    }
}
