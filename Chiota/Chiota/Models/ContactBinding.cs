using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Messenger.Entity;
using Chiota.Models.Classes;
using Xamarin.Forms;

namespace Chiota.Models
{
    public class ContactBinding : BaseModel
    {
        #region Properties

        public Contact Contact { get; }

        public bool IsApproved { get; }

        public ImageSource ImageSource { get; set; }

        public ICommand TapCommand { get; set; }

        #endregion

        #region Constructors

        public ContactBinding(Contact contact, bool isApproved)
        {
            Contact = contact;
            IsApproved = isApproved;

            if(string.IsNullOrEmpty(contact.ImageHash))
                ImageSource = ImageSource.FromFile("account.png");
            else
                ImageSource = ChiotaConstants.IpfsHashGateway + contact.ImageHash;
        }

        #endregion
    }
}
