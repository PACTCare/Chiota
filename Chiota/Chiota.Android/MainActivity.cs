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

  using ImageCircle.Forms.Plugin.Droid;

  using Plugin.CurrentActivity;
  using Plugin.Permissions;

  using Xamarin.Forms;

  [Activity(Label = "Chiota", Icon = "@drawable/icon", Theme = "@style/MainTheme", MainLauncher = false, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation)]
  public class MainActivity : Xamarin.Forms.Platform.Android.FormsAppCompatActivity
  {
    private JobScheduler jobScheduler;

    public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Permission[] grantResults)
    {
      ZXing.Net.Mobile.Android.PermissionsHandler.OnRequestPermissionsResult(requestCode, permissions, grantResults);
      PermissionsImplementation.Current.OnRequestPermissionsResult(requestCode, permissions, grantResults);
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
      Forms.Init(this, bundle);

      this.jobScheduler = (JobScheduler)this.GetSystemService(JobSchedulerService);

      ZXing.Net.Mobile.Forms.Android.Platform.Init();

      FFImageLoading.Forms.Platform.CachedImageRenderer.Init(true);  

      ImageCircleRenderer.Init();

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