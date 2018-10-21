using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.UI.Notifications;

namespace Chiota.UWP.Services
{
    public class Notification
    {
        #region Attributes

        private readonly ToastNotifier notifier;
        private readonly ToastNotification toast;

        #endregion

        #region Constructors

        public Notification(string header, string text)
        {
            //Setup the notifier.
            notifier = ToastNotificationManager.CreateToastNotifier();

            //Setup the toast content.
            var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastText02);
            var toastNodeList = toastXml.GetElementsByTagName("text");
            toastNodeList.Item(0)?.AppendChild(toastXml.CreateTextNode(header));
            toastNodeList.Item(1)?.AppendChild(toastXml.CreateTextNode(text));

            //Setup the toast audio.
            var audio = toastXml.CreateElement("audio");
            audio.SetAttribute("src", "ms-winsoundevent:Notification.SMS");

            //Create the toast.
            toast = new ToastNotification(toastXml);
        }

        #endregion

        #region Methods

        #region Show

        public void Show()
        {
            notifier.Show(toast);
        }

        #endregion

        #endregion
    }
}
