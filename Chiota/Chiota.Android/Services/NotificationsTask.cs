namespace Chiota.Droid.Services
{
  using System.Linq;
  using System.Threading.Tasks;

  using Android.App;
  using Android.Content;
  using Android.Media;
  using Android.OS;
  using Android.Support.V4.App;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services;

  using Java.Lang;

  using Resource = Resource;

  public class NotificationsTask : AsyncTask<Void, Void, Task<bool>>
  {
    protected override async Task<bool> RunInBackground(params Void[] @params)
    {
      var finished = await this.LookForNewNotifications();
      return finished;
    }

    private async Task<bool> LookForNewNotifications()
    {
      // seed needs to be stored on device!!
      var secureStorage = new SecureStorage();
      if (secureStorage.CheckUserStored())
      {
        var user = await secureStorage.GetUser();
        if (user != null)
        {
          // request list is needed for information
          var contactTaskList = user.TangleMessenger.GetJsonMessageAsync<Contact>(user.RequestAddress, 3);
          var approvedContactsTrytes = user.TangleMessenger.GetMessagesAsync(user.ApprovedAddress, 3);

          var contactsOnApproveAddress = IotaHelper.FilterApprovedContacts(await approvedContactsTrytes, user.NtruContactPair);
          var contactRequestList = await contactTaskList;

          var approvedContacts = contactRequestList.Intersect(contactsOnApproveAddress, new ChatAdressComparer()).ToList();

          // currently no messages for contact request due to perfomance issues
          var contactNotificationId = 0;
          foreach (var contact in approvedContacts.Where(c => !c.Rejected))
          {
            var encryptedMessages = await user.TangleMessenger.GetMessagesAsync(contact.ChatAdress);

            if (encryptedMessages.Any(c => !c.Stored))
            {
              var intent = Application.Context.PackageManager.GetLaunchIntentForPackage(Application.Context.PackageName);
              intent.AddFlags(ActivityFlags.ClearTop);
              var pendingIntent = PendingIntent.GetActivity(Application.Context, 0, intent, PendingIntentFlags.UpdateCurrent);
              var builder = new NotificationCompat.Builder(Application.Context)
                .SetAutoCancel(true) // Dismiss from the notif. area when clicked
                .SetContentIntent(pendingIntent)
                .SetContentTitle("Chiota") 
                .SetContentText("New Message from " + contact.Name)
                .SetSound(RingtoneManager.GetDefaultUri(RingtoneType.Notification))
                .SetSmallIcon(Resource.Drawable.reminder);
              var notification = builder.Build();
              var notificationManager = Application.Context.GetSystemService(Context.NotificationService) as NotificationManager;
              notificationManager?.Notify(contactNotificationId, notification);
            }

            contactNotificationId++;
          }
        }
      }

      return true;
    }
  }
}
