namespace UWPRuntimeComponent
{
  using Windows.ApplicationModel.Background;

  public sealed class BackgroundTask : IBackgroundTask
  {
    private BackgroundTaskDeferral deferral;

    public void Run(IBackgroundTaskInstance taskInstance)
    {
      this.deferral = taskInstance.GetDeferral();

      // Run your background task code here
      try
      {
        var settings = Windows.Storage.ApplicationData.Current.LocalSettings;

        settings.Values.Add("BackgroundTask", "Hello from UWP");
      }
      catch
      {
        // ignored
      }

      this.deferral.Complete();
    }
  }
}
