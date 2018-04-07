namespace Chiota.Droid.Services
{
  using System.Linq;

  using Android.Content;
  using Android.OS;

  using Chiota.Models;
  using Chiota.Services;

  using Plugin.LocalNotifications;

  [BroadcastReceiver]
  public class BackgroundReceiver : BroadcastReceiver
  {
    public override async void OnReceive(Context context, Intent intent)
    {
      var pm = (PowerManager)context.GetSystemService(Context.PowerService);
      var wakeLock = pm.NewWakeLock(WakeLockFlags.Partial, "BackgroundReceiver");
      wakeLock.Acquire();

      // seed needs to be stored on device!!
      var secureStorage = new SecureStorage();
      if (secureStorage.CheckUserStored())
      {
        var user = await secureStorage.GetUser();
        if (user != null)
        {
          var contactApprovedList = await user.TangleMessenger.GetJsonMessageAsync<SentDataWrapper<Contact>>(user.ApprovedAddress);

          // Todo also message for a new contact request
          foreach (var contact in contactApprovedList.Where(c => !c.Data.Rejected))
          {
            var encryptedMessages = await user.TangleMessenger.GetMessagesAsync(contact.Data.ChatAdress);
            foreach (var unused in encryptedMessages.Where(c => !c.Stored))
            {
              CrossLocalNotifications.Current.Show(contact.Data.Name, "New Message from " + contact.Data.Name);
            }
          }
        }
      }

      wakeLock.Release();
    }
  }
}