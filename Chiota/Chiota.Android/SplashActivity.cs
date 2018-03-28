namespace Chiota.Droid
{
  using System.Threading.Tasks;

  using Android.App;
  using Android.Content;
  using Android.OS;
  using Android.Support.V7.App;

  using Chiota.Droid;

  [Activity(Theme = "@style/SplashTheme", MainLauncher = true, NoHistory = true)]
    public class SplashActivity : Activity
    {
        static readonly string TAG = "X:" + typeof(SplashActivity).Name;

        public override void OnCreate(Bundle savedInstanceState, PersistableBundle persistentState)
        {
            base.OnCreate(savedInstanceState, persistentState);
        }

        // Launches the startup task
        protected override void OnResume()
        {
            base.OnResume();
          this.StartActivity(new Intent(Application.Context, typeof(MainActivity)));
        }

    }
}