using Android.Content;

namespace Chiota.Droid.Services.BackgroundService
{
    public class MainActivity
    {
        [BroadcastReceiver(Enabled = true, Exported = false)]
        protected internal class BackgroundServiceReciever : BroadcastReceiver
        {
            Context activity;

            public BackgroundServiceReciever()
            {
            }

            public BackgroundServiceReciever(Context activity)
            {
                this.activity = activity;
            }

            public override void OnReceive(Context context, Intent intent)
            {

                if (activity == null)
                {
                }
                else
                {
                    long result = intent.Extras.GetLong(JobSchedulerHelpers.FibonacciResultKey, -1);
                    if (result > -1)
                    {
                    }
                    else
                    {
                    }
                }
            }
        }
    }
}