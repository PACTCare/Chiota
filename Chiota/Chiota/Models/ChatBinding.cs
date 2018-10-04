using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Messenger.Entity;
using Chiota.Models.Classes;
using Xamarin.Forms;

namespace Chiota.Models
{
    public class ChatBinding : BaseModel
    {
        #region Properties

        public string Name { get; }

        public string LastMessage { get; set; }

        public DateTime LastMessageDateTime { get; set; }

        public ImageSource ImageSource { get; }

        #endregion

        #region Constructors

        public ChatBinding(Contact contact)
        {
            Name = contact.Name;

            if (string.IsNullOrEmpty(contact.ImageHash))
                ImageSource = ImageSource.FromFile("account.png");
            else
                ImageSource = ImageSource.FromUri(new Uri(ChiotaConstants.IpfsHashGateway + contact.ImageHash));
        }

        #endregion
    }
}
