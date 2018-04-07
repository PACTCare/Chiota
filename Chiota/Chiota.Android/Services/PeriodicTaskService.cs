namespace Chiota.Droid.Services
{
  using System.Threading;
  using System.Threading.Tasks;

  using Android.App;
  using Android.Content;
  using Android.OS;
  using Android.Runtime;

  using Chiota.Messages;

  using Xamarin.Forms;

  //Todo https://blog.xamarin.com/replacing-services-jobs-android-oreo-8-0/
  [Service]
  public class PeriodicTaskService : Service
  {
    private CancellationTokenSource cts;

    public override IBinder OnBind(Intent intent)
    {
      return null;
    }

    public override StartCommandResult OnStartCommand(Intent intent, StartCommandFlags flags, int startId)
    {
      this.cts = new CancellationTokenSource();

      Task.Run(
        () =>
          {
            try
            {
              // start backgroundreceiver
              var alarmIntent = new Intent(this, typeof(BackgroundReceiver));

              var pending = PendingIntent.GetBroadcast(this, 0, alarmIntent, PendingIntentFlags.UpdateCurrent);

              var alarmManager = this.GetSystemService(AlarmService).JavaCast<AlarmManager>();

              // alarmManager.Set(AlarmType.ElapsedRealtime, SystemClock.ElapsedRealtime() + 3 * 1000, pending);
              alarmManager.SetRepeating(
                AlarmType.RtcWakeup,
                SystemClock.ElapsedRealtime(),
                1000 * 60 * 15, // updates every 15 minutes
                pending);
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
              if (this.cts.IsCancellationRequested)
              {
                var message = new CancelledMessage();
                Device.BeginInvokeOnMainThread(() => MessagingCenter.Send(message, "CancelledMessage"));
              }
            }
          },
        this.cts.Token);

      return StartCommandResult.Sticky;
    }

    public override void OnDestroy()
    {
      if (this.cts != null)
      {
        this.cts.Token.ThrowIfCancellationRequested();

        this.cts.Cancel();
      }

      base.OnDestroy();
    }
  }
}