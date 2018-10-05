using Chiota.Base;
using Chiota.Views.Messenger;

namespace Chiota
{
    /// <summary>
    /// The app.
    /// </summary>
    public partial class App
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="App"/> class.
        /// </summary>
        public App()
        {
            InitializeComponent();

            MainPage = new SplashView();
        }

        /// <summary>
        /// The on resume.
        /// </summary>
        protected override void OnResume()
        {
            // Handle when your app resumes
        }

        /// <summary>
        /// The on sleep.
        /// </summary>
        protected override void OnSleep()
        {
        }

        /// <summary>
        /// The on start.
        /// </summary>
        protected override void OnStart()
        {
        }
    }
}