using Xamarin.Forms.Xaml;

[assembly: XamlCompilation(XamlCompilationOptions.Compile)]

namespace Chiota
{
  using Chiota.CustomCells;
  using Chiota.Services;

  using Xamarin.Forms;

  using ContactPage = Views.ContactPage;
  using LoginPage = Chiota.Views.LoginPage;

  /// <summary>
  /// The app.
  /// </summary>
  public partial class App : Application
  {
    public App()
    {
      this.InitializeComponent();
      var secureStorage = new SecureStorage();
      if (secureStorage.CheckUserStored())
      {
        this.MainPage = new NavigationPage(new ContactPage(secureStorage.GetUser()));
      }
      else
      {
        this.MainPage = new NavigationPage(new LoginPage());
      }
    }

    public static string AppName => "Chiota";

    protected override void OnStart()
    {
      // Handle when your app starts
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
