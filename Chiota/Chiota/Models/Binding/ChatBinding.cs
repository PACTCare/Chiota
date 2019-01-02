#region References

using System;
using System.IO;
using Chiota.Helper;
using Chiota.Models.Database;
using Chiota.Models.Database.Base;
using Xamarin.Forms;

#endregion

namespace Chiota.Models.Binding
{
    public class ChatBinding : BaseModel
    {
        #region Properties

        public DbContact Contact { get; set; }

        public string LastMessage { get; set; }

        public DateTime LastMessageDateTime { get; set; }

        public ImageSource ImageSource { get; }

        #endregion

        #region Constructors

        public ChatBinding(DbContact contact, string lastMessage, DateTime lastMessageDateTime)
        {
            Contact = contact;

            LastMessage = lastMessage;
            LastMessageDateTime = lastMessageDateTime;

            if (!string.IsNullOrEmpty(contact.ImageBase64))
                ImageSource = ImageSource.FromStream(() => new MemoryStream(Convert.FromBase64String(contact.ImageBase64)));
            else if (!string.IsNullOrEmpty(contact.ImagePath))
                ImageSource = ChiotaConstants.IpfsHashGateway + contact.ImagePath;
            else
                ImageSource = null;
        }

        #endregion
    }
}
