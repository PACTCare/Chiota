namespace Chiota.Droid
{
  using Android.App;
  using Android.Content.PM;
  using Android.OS;

  using Chiota;

  using ImageCircle.Forms.Plugin.Droid;

  using Plugin.LocalNotifications;

  using Plugin.Permissions;

  [Activity(Label = "FlorenceApp", Icon = "@drawable/icon", Theme = "@style/MainTheme", MainLauncher = false, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation)]
  public class MainActivity : Xamarin.Forms.Platform.Android.FormsAppCompatActivity
  {
    protected override void OnCreate(Bundle bundle)
    {
      TabLayoutResource = Resource.Layout.Tabbar;
      ToolbarResource = Resource.Layout.Toolbar;

      // ToolbarResource = Resource.Id.toolbar;
      base.OnCreate(bundle);

      Xamarin.Forms.Forms.Init(this, bundle);

      ZXing.Net.Mobile.Forms.Android.Platform.Init();

      ImageCircleRenderer.Init();

      // Changes the notification icon
      LocalNotificationsImplementation.NotificationIconId = Resource.Drawable.icon;

      this.LoadApplication(new App());
    }

    // https://github.com/jamesmontemagno/MediaPlugin#important-permission-information
    public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Permission[] grantResults)
    {
      ZXing.Net.Mobile.Android.PermissionsHandler.OnRequestPermissionsResult(requestCode, permissions, grantResults);
      PermissionsImplementation.Current.OnRequestPermissionsResult(requestCode, permissions, grantResults);
    }
  }
}