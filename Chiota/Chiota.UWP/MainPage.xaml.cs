using Chiota.Services.Database;
using Xamarin.Essentials;

namespace Chiota.UWP
{
  using System;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services;

  using Windows.ApplicationModel.Background;
  using Windows.UI.Notifications;

  using Chiota.Persistence;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Iota;
  using Chiota.Services.UserServices;

  using Pact.Palantir.Entity;
  using Pact.Palantir.Usecase;
  using Pact.Palantir.Usecase.GetContacts;

  using Tangle.Net.Entity;
    using Contact = Pact.Palantir.Entity.Contact;

    /// <summary>
    /// The main page.
    /// </summary>
    public sealed partial class MainPage
  {
    private const string BackgroundTaskName = "UWPNotifications";

    public MainPage()
    {
      this.InitializeComponent();

      ZXing.Net.Mobile.Forms.WindowsUniversal.ZXingScannerViewRenderer.Init();     
      
      this.LoadApplication(new Chiota.App());

      if (this.IsRegistered())
      {
        this.Unregister();
      }

      this.Register();
    }

    private async Task Register()
    {
      BackgroundExecutionManager.RemoveAccess();

      var requestAccessStatus = await BackgroundExecutionManager.RequestAccessAsync();

      var builder = new BackgroundTaskBuilder
      {
        Name = BackgroundTaskName,
        TaskEntryPoint =
                          "UWPRuntimeComponent.SystemBackgroundTask"
      };

      // builder.SetTrigger(new SystemTrigger(SystemTriggerType.InternetAvailable, false));
      if (requestAccessStatus == BackgroundAccessStatus.AlwaysAllowed ||
          requestAccessStatus == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
      {
        builder.SetTrigger(new TimeTrigger(15, false));
        var task = builder.Register();
        task.Completed += this.TaskCompleted;
      }
    }

    private async void TaskCompleted(BackgroundTaskRegistration sender, BackgroundTaskCompletedEventArgs args)
    {
        var isUserStored = DatabaseService.User.IsUserStored();
            if (!isUserStored)
      {
        return;
      }

            var interactor = DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>();
      var response = await interactor.ExecuteAsync(
                       new GetContactsRequest
                         {
                           RequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                           PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
                         });

      if (response.Code != ResponseCode.Success)
      {
        return;
      }

      // currently no messages for contact request due to perfomance issues
      foreach (var contact in response.ApprovedContacts.Where(c => !c.Rejected))
      {
        // TODO: currently not working since transaction cache gets wiped on logout
        //var encryptedMessages = await user.TangleMessenger.GetMessagesAsync(contact.ChatAddress);

        //if (encryptedMessages.Any(c => !c.Stored))
        //{
        //  this.CreateNotification(contact);
        //}
      }
    }

    private void CreateNotification(Contact contact)
    {
      var toastNotifier = ToastNotificationManager.CreateToastNotifier();
      var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastText02);
      var toastNodeList = toastXml.GetElementsByTagName("text");
      toastNodeList.Item(0)?.AppendChild(toastXml.CreateTextNode("Chiota"));
      toastNodeList.Item(1)?.AppendChild(toastXml.CreateTextNode("New message from " + contact.Name));
      var audio = toastXml.CreateElement("audio");
      audio.SetAttribute("src", "ms-winsoundevent:Notification.SMS");

      var toast = new ToastNotification(toastXml);
      toastNotifier.Show(toast);
    }

    private void Unregister()
    {
      var taskName = BackgroundTaskName;

      foreach (var task in BackgroundTaskRegistration.AllTasks)
      {
        if (task.Value.Name == taskName)
        {
          task.Value.Unregister(true);
        }
      }
    }

    private bool IsRegistered()
    {
      var taskName = BackgroundTaskName;

      foreach (var task in BackgroundTaskRegistration.AllTasks)
      {
        if (task.Value.Name == taskName)
        {
          return true;
        }
      }

      return false;
    }
  }
}
