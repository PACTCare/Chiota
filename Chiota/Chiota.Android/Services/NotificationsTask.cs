namespace Chiota.Droid.Services
{
  using System.Linq;
  using System.Threading.Tasks;

  using Android.App;
  using Android.Content;
  using Android.Media;
  using Android.OS;
  using Android.Support.V4.App;

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
          var contactApprovedList = await user.TangleMessenger.GetJsonMessageAsync<SentDataWrapper<Contact>>(user.ApprovedAddress);

          // currently no messages for contact request due to perfomance issues
          foreach (var contact in contactApprovedList.Where(c => !c.Data.Rejected))
          {
            var encryptedMessages = await user.TangleMessenger.GetMessagesAsync(contact.Data.ChatAdress);

            foreach (var unused in encryptedMessages.Where(c => !c.Stored))
            {
              var builder = new NotificationCompat.Builder(Application.Context)
                .SetAutoCancel(true) // Dismiss from the notif. area when clicked
                .SetContentTitle(contact.Data.Name) // Set its title
                .SetContentText("New Message from " + contact.Data.Name)
                .SetSound(RingtoneManager.GetDefaultUri(RingtoneType.Notification))
                .SetSmallIcon(Resource.Drawable.reminder);
              var notification = builder.Build();
              var notificationManager = Application.Context.GetSystemService(Context.NotificationService) as NotificationManager;
              notificationManager?.Notify(0, notification);
            }
          }
        }
      }

      return true;
    }
  }
}
