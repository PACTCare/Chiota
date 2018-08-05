namespace Chiota.Droid
{
    using Android.App;
    using Android.Content;

    [Activity(Theme = "@style/SplashTheme", MainLauncher = true, NoHistory = true)]
    public class SplashActivity : Activity
    {
        // Launches the startup task
        protected override void OnResume()
        {
            base.OnResume();
            this.StartActivity(new Intent(Application.Context, typeof(MainActivity)));
        }
    }
}