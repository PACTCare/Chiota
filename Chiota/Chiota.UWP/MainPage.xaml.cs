namespace Chiota.UWP
{
  using System;
  using System.Diagnostics;
  using System.Threading.Tasks;

  using Windows.ApplicationModel.Background;

  /// <summary>
  /// The main page.
  /// </summary>
  public sealed partial class MainPage
  {
    private const string BackgroundTaskName = "MyBackgroundTask";

    public MainPage()
    {
      this.InitializeComponent();

      ZXing.Net.Mobile.Forms.WindowsUniversal.ZXingScannerViewRenderer.Init();

      this.LoadApplication(new Chiota.App());

      if (this.IsRegistered())
      {
        this.Unregister();
      }

      this.Register();
    }

    private async Task Register()
    {
      BackgroundExecutionManager.RemoveAccess();

      await BackgroundExecutionManager.RequestAccessAsync();

      var builder = new BackgroundTaskBuilder
                      {
                        Name = BackgroundTaskName,
                        TaskEntryPoint =
                          "UWPRuntimeComponent.BackgroundTask"
      };

      // builder.SetTrigger(new SystemTrigger(SystemTriggerType.InternetAvailable, false));
      builder.SetTrigger(new TimeTrigger(15, false));

      var task = builder.Register();

      task.Completed += this.Task_Completed;

      Debug.WriteLine("[PeriodicBackgroundService] Background task registered");
    }

    private async void Task_Completed(BackgroundTaskRegistration sender, BackgroundTaskCompletedEventArgs args)
    {
      var settings = Windows.Storage.ApplicationData.Current.LocalSettings;
      var key = BackgroundTaskName;
      var message = settings.Values[key];

      // Run your background task code here
      // notification here
      Debug.WriteLine("[PeriodicBackgroundService] Background task completed");
    }

    private void Unregister()
    {
      var taskName = BackgroundTaskName;

      foreach (var task in BackgroundTaskRegistration.AllTasks)
      {
        if (task.Value.Name == taskName)
        {
          task.Value.Unregister(true);
        }
      }
    }

    private bool IsRegistered()
    {
      var taskName = BackgroundTaskName;

      foreach (var task in BackgroundTaskRegistration.AllTasks)
      {
        if (task.Value.Name == taskName)
        {
          return true;
        }
      }

      return false;
    }
  }
}
