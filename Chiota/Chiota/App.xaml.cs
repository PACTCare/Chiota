namespace Chiota
{
  using System;

  using Chiota.Classes;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;

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