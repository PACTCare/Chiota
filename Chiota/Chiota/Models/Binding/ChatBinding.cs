using System;
using Chiota.Helper;
using Chiota.Models.Database.Base;
using Pact.Palantir.Entity;
using Xamarin.Forms;

namespace Chiota.Models.Binding
{
    public class ChatBinding : BaseModel
    {
        #region Properties

        public string Name { get; }

        public string LastMessage { get; set; }

        public DateTime LastMessageDateTime { get; set; }

        public ImageSource ImageSource { get; }

        public Contact Contact { get; }

        #endregion

        #region Constructors

        public ChatBinding(Contact contact)
        {
            Name = contact.Name;

            if (string.IsNullOrEmpty(contact.ImagePath))
                ImageSource = ImageSource.FromFile("account.png");
            else
                ImageSource = ImageSource.FromUri(new Uri(ChiotaConstants.IpfsHashGateway + contact.ImagePath));

            Contact = contact;
        }

        #endregion
    }
}
