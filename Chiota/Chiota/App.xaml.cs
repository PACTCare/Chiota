namespace Chiota
{
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Navigation;
  using Chiota.Services.Storage;
  using Chiota.Services.UserServices;
  using Chiota.Views;

  using Plugin.Connectivity;

  using Xamarin.Forms;

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

      var navigationService = DependencyResolver.Resolve<INavigationService>();

      if (CrossConnectivity.Current.IsConnected)
      {
        var secureStorage = new SecureStorage();
        if (secureStorage.CheckUserStored())
        {
          var user = await secureStorage.GetUser();

          if (user != null)
          {
            UserService.SetCurrentUser(user);
            this.MainPage = new NavigationPage(navigationService.LoggedInEntryPoint);
          }
          else
          {
            this.MainPage = new NavigationPage(navigationService.LoginEntryPoint);
          }
        }
        else
        {
          this.MainPage = new NavigationPage(navigationService.LoginEntryPoint);
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
