using Chiota.Classes;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Storage;
using Chiota.Services.UserServices;
using Chiota.Views;

using Plugin.Connectivity;

using Xamarin.Forms;

namespace Chiota
{
    /// <summary>
    /// The app.
    /// </summary>
    public partial class App : Application
    {
        public App()
        {
            this.InitializeComponent();

            AppNavigation.ShowStartUp();
        }

        protected override void OnStart()
        {
            // Handle when your app starts
        }

        protected override void OnSleep()
        {
            // Handle when your app sleeps
        }

        protected override void OnResume()
        {
            // Handle when your app resumes
        }
    }
}
