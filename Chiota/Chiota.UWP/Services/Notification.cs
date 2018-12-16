#region References

using Windows.UI.Notifications;
using Chiota.Services;
using Xamarin.Forms;

#endregion

[assembly: Dependency(typeof(Chiota.UWP.Services.Notification))]
namespace Chiota.UWP.Services
{
    public sealed class Notification : INotification
    {
        #region Methods

        #region Show

        public void Show(string header, string text)
        {
            //Setup the notifier.
            var notifier = ToastNotificationManager.CreateToastNotifier();

            //Setup the toast content.
            var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastText02);
            var toastNodeList = toastXml.GetElementsByTagName("text");
            toastNodeList.Item(0)?.AppendChild(toastXml.CreateTextNode(header));
            toastNodeList.Item(1)?.AppendChild(toastXml.CreateTextNode(text));

            //Setup the toast audio.
            var audio = toastXml.CreateElement("audio");
            audio.SetAttribute("src", "ms-winsoundevent:Notification.SMS");

            //Create the toast.
            var toast = new ToastNotification(toastXml);
            notifier.Show(toast);
        }

        #endregion

        #endregion
    }
}
