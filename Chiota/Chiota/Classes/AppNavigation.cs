using System;
using System.Collections.Generic;
using System.Text;
using Chiota.ViewModels.Classes;

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
        /*public static void ShowSplashPage()
        {
            //Create new navigation container
            var navigation = new NavigationPage(new SplashPage());
            var container = SetNavigationStyles(navigation);

            Application.Current.MainPage = container;
        }*/

        /// <summary>
        /// Set the navigation styles of the application.
        /// </summary>
        /// <param name="page"></param>
        /// <returns></returns>
        /*private static NavigationPage SetNavigationStyles(NavigationPage page)
        {
            page.BarBackgroundColor = (Color)Application.Current.Resources["AccentColor"];
            page.BarTextColor = (Color)Application.Current.Resources["TextColor"];

            return page;
        }*/

        #endregion
    }
}
