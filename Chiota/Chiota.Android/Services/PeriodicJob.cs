namespace Chiota.Droid.Services
{
  using System.Threading;
  using System.Threading.Tasks;

  using Android.App;
  using Android.App.Job;
  using Android.OS;

  [Service(Name = "chiotaapp.chiotaapp.PeriodicJob", Permission = "android.permission.BIND_JOB_SERVICE")]
  public class PeriodicJob : JobService
  {
    private CancellationTokenSource cts;

    public override bool OnStartJob(JobParameters jobParameters)
    {
      // Called by the operating system when starting the service.
      // Start up a thread, do work on the thread.
      this.cts = new CancellationTokenSource();

      Task.Run(
        () =>
          {
            try
            {
              var notification = new NotificationsTask();
              notification.Execute();
            }
            catch (OperationCanceledException)
            {
            }
          },
        this.cts.Token);

      return true; 
    }

    public override bool OnStopJob(JobParameters jobParameters)
    {
      // Called by Android when it has to terminate a running service.
      if (this.cts != null)
      {
        this.cts.Token.ThrowIfCancellationRequested();

        this.cts.Cancel();
      }

      return true; // false don't reschedule the job.
    }
  }
}