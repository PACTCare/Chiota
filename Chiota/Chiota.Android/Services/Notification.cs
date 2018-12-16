#region References

using Android.App;
using Android.Content;
using Android.Media;
using Android.OS;
using Android.Support.V4.App;
using Chiota.Services;
using Xamarin.Forms;
using Application = Android.App.Application;
using Notification = Chiota.Droid.Services.Notification;

#endregion

[assembly: Dependency(typeof(Notification))]
namespace Chiota.Droid.Services
{
    public class Notification : INotification
    {
        #region Methods

        #region Show

        public void Show(string header, string text)
        {
            var intent = Application.Context.PackageManager.GetLaunchIntentForPackage(Application.Context.PackageName);
            intent.AddFlags(ActivityFlags.ClearTop);
            var pendingIntent = PendingIntent.GetActivity(Application.Context, 0, intent, PendingIntentFlags.UpdateCurrent);
            var notificationManager = Application.Context.GetSystemService(Context.NotificationService) as NotificationManager;

            var builder = new NotificationCompat.Builder(Application.Context, "channel-chiota")
                .SetAutoCancel(true)
                .SetContentIntent(pendingIntent).SetContentTitle(header)
                .SetContentText(text)
                .SetSound(RingtoneManager.GetDefaultUri(RingtoneType.Notification))
                .SetSmallIcon(Resource.Drawable.reminder);

            if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
            {
                var mChannel = new NotificationChannel("channel-chiota", "Chiota", NotificationImportance.High);
                mChannel.EnableVibration(true);
                mChannel.LockscreenVisibility = NotificationVisibility.Public;
                notificationManager?.CreateNotificationChannel(mChannel);
            }

            var notification = builder.Build();
            notificationManager?.Notify(0, notification);
        }

        #endregion

        #endregion
    }
}
