#region References

using Android.Content;

#endregion

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
            }
        }
    }
}