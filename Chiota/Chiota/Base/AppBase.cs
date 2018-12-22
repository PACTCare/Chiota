#region References

using System;
using System.Linq;
using Chiota.Models.Database;
using Chiota.Services.BackgroundServices;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Chiota.Services.Database.Base;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views.Authentication;
using Chiota.Views.Tabbed;
using Xamarin.Forms;

#endregion

namespace Chiota.Base
{
    public static class AppBase
    {
        #region Attributes

        private static NavigationImplementation _navigation;

        #endregion

        #region Properties

        public static NavigationImplementation GetNavigationInstance()
        {
            return _navigation ?? (_navigation = new NavigationImplementation());
        }

        public static DatabaseService Database { get; set; }

        #endregion

        #region Methods

        #region ShowStartUp

        public static void ShowStartUp()
        {
            NavigationPage container;

            //Delete the secure storage.
            //SecureStorage.RemoveAll();
            
            //Get information, if there exist a user in the database.
            var sqlite = DependencyService.Get<ISqlite>().GetDatabaseConnection();
            var result = sqlite.Table<DbUser>();

            var isUserExist = false;
            try
            {
                if (result.Any())
                    isUserExist = true;
            }
            catch (Exception)
            {
                //Ignore
            }

            if (isUserExist)
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
            try
            {
                //Start the background service for receiving notifications of the tangle,
                //to update the user outside of the app.
                DependencyService.Get<IBackgroundJobWorker>().Run<ContactRequestBackgroundJob>(UserService.CurrentUser);
                DependencyService.Get<IBackgroundJobWorker>().Run<ChatMessageBackgroundJob>(UserService.CurrentUser);
            }
            catch (Exception ex)
            {
                //Ignore
            }

            // Show the page.
            var container = SetNavigationStyles(new NavigationPage(new TabbedNavigationView()));
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