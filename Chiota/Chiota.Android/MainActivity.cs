using Android.Util;
using Chiota.Droid.Services.BackgroundService;
#region References

using ImageCircle.Forms.Plugin.Droid;
using Android.App;
using Android.App.Job;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Chiota.Services.DependencyInjection;
using Plugin.CurrentActivity;
using Plugin.Permissions;
using Xamarin.Forms;
using static Chiota.Droid.Services.BackgroundService.MainActivity;

#endregion

namespace Chiota.Droid
{
    [Activity(Label = "Chiota", Icon = "@drawable/icon", Theme = "@style/MainTheme", MainLauncher = false)]
    public class MainActivity : Xamarin.Forms.Platform.Android.FormsAppCompatActivity
    {
        #region Attributes

        private JobScheduler _jobScheduler;
        private BackgroundServiceReciever _receiver;

        #endregion

        #region Methods

        #region OnCreate

        protected override void OnCreate(Bundle bundle)
        {
            base.OnCreate(bundle);

            //Add the injection module.
            DependencyResolver.Modules.Add(new InjectionModule());

            //Set the layout for tab and toolbar.
            TabLayoutResource = Resource.Layout.Tabbar;
            ToolbarResource = Resource.Layout.Toolbar;

            //Prepare background services.
            _receiver = new BackgroundServiceReciever(this);

            //Set the current activity.
            CrossCurrentActivity.Current.Activity = this;

            //Pre initialization. 
            Forms.SetFlags("FastRenderers_Experimental");
            Xamarin.Essentials.Platform.Init(this, bundle);
            Rg.Plugins.Popup.Popup.Init(this, bundle);

            //Init Xamarin.Forms.
            Forms.Init(this, bundle);

            //Post initialization.
            ImageCircleRenderer.Init();
            ZXing.Net.Mobile.Forms.Android.Platform.Init();

            //Init the background services.
            DependencyService.Get<BackgroundJobWorker>().Init(this, (JobScheduler)GetSystemService(JobSchedulerService));

            //Load the application.
            LoadApplication(new App());
        }

        #endregion

        #region OnResume

        protected override void OnResume()
        {
            base.OnResume();

            BaseContext.RegisterReceiver(_receiver, new IntentFilter(BackgroundServiceHelpers.ResultKey));

            var filter = new IntentFilter();
            filter.AddAction(BackgroundServiceHelpers.JobActionKey);
            RegisterReceiver(_receiver, filter);
        }

        #endregion

        #region OnPause

        protected override void OnPause()
        {
            BaseContext.UnregisterReceiver(_receiver);

            base.OnPause();
        }

        #endregion

        #region OnRequestPermissionsResult

        public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Permission[] grantResults)
        {
            ZXing.Net.Mobile.Android.PermissionsHandler.OnRequestPermissionsResult(requestCode, permissions, grantResults);
            PermissionsImplementation.Current.OnRequestPermissionsResult(requestCode, permissions, grantResults);
            Xamarin.Essentials.Platform.OnRequestPermissionsResult(requestCode, permissions, grantResults);

            base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        }

        #endregion

        #endregion
    }
}