namespace Chiota.Droid.Services
{
  using System.Linq;
  using System.Threading.Tasks;

  using Android.App;
  using Android.Content;
  using Android.Media;
  using Android.OS;
  using Android.Support.V4.App;

  using Chiota.Messenger.Comparison;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.GetContacts;
  using Chiota.Persistence;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;

  using Java.Lang;

  using Plugin.Connectivity;

  using Tangle.Net.Entity;

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
      if (CrossConnectivity.Current.IsConnected)
      {
        // seed needs to be stored on device!!
        if (!SecureStorage.IsUserStored)
        {
          return true;
        }

        var user = await SecureStorage.GetUser();
        if (user == null)
        {
          return true;
        }

        var interactor = DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>();
        var response = await interactor.ExecuteAsync(
                         new GetContactsRequest
                           {
                             ContactRequestAddress = new Address(user.RequestAddress),
                             PublicKeyAddress = new Address(user.PublicKeyAddress)
                           });

        if (response.Code != ResponseCode.Success)
        {
          return true;
        }

        // currently no messages for contact request due to perfomance issues
        var contactNotificationId = 0;
        foreach (var contact in response.ApprovedContacts.Where(c => !c.Rejected))
        {
          // TODO: currently not working since transaction cache gets wiped on logout
          //var encryptedMessages = await user.TangleMessenger.GetMessagesAsync(contact.ChatAddress);

          //if (encryptedMessages.Any(c => !c.Stored))
          //{
          //  this.CreateNotification(contactNotificationId, contact);
          //}

          //contactNotificationId++;
        }
      }

      return true;
    }

    private void CreateNotification(int contactNotificationId, Contact contact)
    {
      var intent = Application.Context.PackageManager.GetLaunchIntentForPackage(Application.Context.PackageName);
      intent.AddFlags(ActivityFlags.ClearTop);
      var pendingIntent = PendingIntent.GetActivity(
        Application.Context,
        0,
        intent,
        PendingIntentFlags.UpdateCurrent);

      var notificationManager =
        Application.Context.GetSystemService(Context.NotificationService) as NotificationManager;

      var builder = new NotificationCompat.Builder(Application.Context, "channel-chiota")
        .SetAutoCancel(true) // Dismiss from the notif. area when clicked
        .SetContentIntent(pendingIntent).SetContentTitle("Chiota")
        .SetContentText("New Message from " + contact.Name)
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

      notificationManager?.Notify(contactNotificationId, notification);
    }
  }
}
