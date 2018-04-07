namespace Chiota.UWP
{
  using System;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services;

  using Plugin.LocalNotifications;

  using Windows.ApplicationModel.Background;
  using Windows.UI.Xaml;

  /// <summary>
  /// An empty page that can be used on its own or navigated to within a Frame.
  /// </summary>
  public sealed partial class MainPage
  {
    public MainPage()
    {
      this.InitializeComponent();
      this.LoadApplication(new Chiota.App());

      ZXing.Net.Mobile.Forms.WindowsUniversal.ZXingScannerViewRenderer.Init();

      if (this.IsRegistered())
      {
        this.Deregister();
      }

      this.Loaded += this.MainPageLoaded;
    }

    private async void MainPageLoaded(object sender, RoutedEventArgs e)
    {
      await this.BackgroundTask();
    }

    private void Deregister()
    {
      var taskName = "BackgroundTask";

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
      var taskName = "BackgroundTask";

      foreach (var task in BackgroundTaskRegistration.AllTasks)
      {
        if (task.Value.Name == taskName)
        {
          return true;
        }
      }

      return false;
    }

    private async Task BackgroundTask()
    {
      BackgroundExecutionManager.RemoveAccess();

      await BackgroundExecutionManager.RequestAccessAsync();

      var builder = new BackgroundTaskBuilder
                      {
                        Name = "BackgroundTask",
                        TaskEntryPoint = "UWPRuntimeComponent.BackgroundTask"
                      };

      builder.SetTrigger(new TimeTrigger(15, false));
      var task = builder.Register();
      task.Completed += this.TaskCompleted;
    }

    private async void TaskCompleted(BackgroundTaskRegistration sender, BackgroundTaskCompletedEventArgs args)
    {
      var settings = Windows.Storage.ApplicationData.Current.LocalSettings;
      var key = "BackgroundTask";
      var message = settings.Values[key].ToString();

      // Run your background task code here
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
    }
  }
}
