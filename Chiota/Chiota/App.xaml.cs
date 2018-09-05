namespace Chiota
{
  using Chiota.Classes;
  using Chiota.Services.DependencyInjection;

  /// <summary>
  /// The app.
  /// </summary>
  public partial class App
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="App"/> class.
    /// </summary>
    public App()
    {
      this.InitializeComponent();

      AppNavigation.ShowStartUp();
    }

    /// <summary>
    /// The on resume.
    /// </summary>
    protected override void OnResume()
    {
      // Handle when your app resumes
    }

    /// <summary>
    /// The on sleep.
    /// </summary>
    protected override void OnSleep()
    {
      // Handle when your app sleeps
    }

    /// <summary>
    /// The on start.
    /// </summary>
    protected override void OnStart()
    {
      DependencyResolver.Init();
    }
  }
}