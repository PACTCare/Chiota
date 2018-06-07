namespace Chiota
{
  using Chiota.Models;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.Views;

  using Plugin.Connectivity;

  using Xamarin.Forms;

  using ContactPage = Views.ContactPage;
  using LoginPage = Views.LoginPage;

  /// <summary>
  /// The app.
  /// </summary>
  public partial class App : Application
  {
    public App()
    {
      this.InitializeComponent();
      this.MainPage = new GreyPage();
    }

    public static string AppName => "Chiota";

    protected override async void OnStart()
    {
      DependencyResolver.Init();

      if (CrossConnectivity.Current.IsConnected)
      {
        // First time set default values
        if (!Current.Properties.ContainsKey(ChiotaConstants.SettingsPowKey))
        {
          Current.Properties[ChiotaConstants.SettingsPowKey] = true;
          Current.Properties[ChiotaConstants.SettingsNodeKey] = "https://field.carriota.com:443";
        }

        var secureStorage = new SecureStorage();
        if (secureStorage.CheckUserStored())
        {
          var user = await secureStorage.GetUser();

          // user = null => setup probably interrupted
          this.MainPage = user != null ? new NavigationPage(new ContactPage(user)) : new NavigationPage(new LoginPage());
        }
        else
        {
          this.MainPage = new NavigationPage(new LoginPage());
        }
      }
      else
      {
        this.MainPage = new NavigationPage(new OfflinePage());
      }
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
