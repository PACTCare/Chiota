using Android.Runtime;
using Chiota.Droid.Services.BackgroundService;
using Chiota.Services.BackgroundServices.Base;
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
            Forms.Init(this, bundle);
            ImageCircleRenderer.Init();

            ZXing.Net.Mobile.Forms.Android.Platform.Init();

            //Init the background services.
            DependencyService.Get<BackgroundWorker>().Init(this, (JobScheduler)GetSystemService(JobSchedulerService));

            this.LoadApplication(new App());
        }
    }
}