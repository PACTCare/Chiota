namespace UWPRuntimeComponent
{
  using Windows.ApplicationModel.Background;

  public sealed class SystemBackgroundTask : IBackgroundTask
  {
    private BackgroundTaskDeferral deferral;

    public async void Run(IBackgroundTaskInstance taskInstance)
    {
      taskInstance.Canceled += this.TaskInstanceCanceled;
      this.deferral = taskInstance.GetDeferral();
     
      // Run your background task code here
      this.deferral.Complete();
    }

    private void TaskInstanceCanceled(IBackgroundTaskInstance sender, BackgroundTaskCancellationReason reason)
    {
      this.deferral.Complete();
    }   
  }
}
