namespace UWPRuntimeComponent
{
  using Windows.ApplicationModel.Background;

  public sealed class BackgroundTask : IBackgroundTask
  {
    private BackgroundTaskDeferral deferral;

    public async void Run(IBackgroundTaskInstance taskInstance)
    {
      this.deferral = taskInstance.GetDeferral();

      // Run your background task code here

      this.deferral.Complete();
    }
  }
}
