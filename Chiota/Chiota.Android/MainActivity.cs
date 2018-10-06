using Android.Runtime;
using ImageCircle.Forms.Plugin.Droid;

namespace Chiota.Droid
{
    using Android.App;
    using Android.App.Job;
    using Android.Content;
    using Android.Content.PM;
    using Android.OS;

    using Chiota;
    using Chiota.Droid.Services;
    using Chiota.Services.DependencyInjection;

    using Plugin.CurrentActivity;
    using Plugin.Permissions;

    using Xamarin.Forms;

    [Activity(Label = "Chiota", Icon = "@drawable/icon", Theme = "@style/MainTheme", MainLauncher = false)]
    public class MainActivity : Xamarin.Forms.Platform.Android.FormsAppCompatActivity
    {
        private JobScheduler jobScheduler;

        public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Permission[] grantResults)
        {
            ZXing.Net.Mobile.Android.PermissionsHandler.OnRequestPermissionsResult(requestCode, permissions, grantResults);
            PermissionsImplementation.Current.OnRequestPermissionsResult(requestCode, permissions, grantResults);
            Xamarin.Essentials.Platform.OnRequestPermissionsResult(requestCode, permissions, grantResults);

            base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        }

        protected override void OnCreate(Bundle bundle)
        {
            DependencyResolver.Modules.Add(new InjectionModule());

            TabLayoutResource = Resource.Layout.Tabbar;
            ToolbarResource = Resource.Layout.Toolbar;

            // ToolbarResource = Resource.Id.toolbar;
            base.OnCreate(bundle);
            CrossCurrentActivity.Current.Activity = this;

            // https://docs.microsoft.com/de-de/xamarin/xamarin-forms/internals/fast-renderers
            Forms.SetFlags("FastRenderers_Experimental");
            Xamarin.Essentials.Platform.Init(this, bundle);
            Rg.Plugins.Popup.Popup.Init(this, bundle);
            SQLitePCL.Batteries.Init();
            Forms.Init(this, bundle);
            ImageCircleRenderer.Init();

            this.jobScheduler = (JobScheduler)this.GetSystemService(JobSchedulerService);

            ZXing.Net.Mobile.Forms.Android.Platform.Init();

            this.LoadApplication(new App());
            this.WireUpLongRunningTask();
        }

        private void WireUpLongRunningTask()
        {
            // https://stackoverflow.com/questions/38344220/job-scheduler-not-running-on-android-n
            var javaClass = Java.Lang.Class.FromType(typeof(PeriodicJob));
            var compName = new ComponentName(this, javaClass);
            var jobInfo = new JobInfo.Builder(1, compName)
              .SetRequiredNetworkType(NetworkType.Any)
              .SetPeriodic(1000 * 60 * 15).Build();
            var result = this.jobScheduler.Schedule(jobInfo);
        }
    }
}