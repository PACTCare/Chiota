using System;
using System.IO;
using Chiota.Helper;
using Chiota.Models.Database.Base;
using Pact.Palantir.Entity;
using Xamarin.Forms;

namespace Chiota.Models.Binding
{
    public class ContactBinding : BaseModel
    {
        #region Properties

        public Contact Contact { get; }

        public bool IsApproved { get; }

        public string ImageBase64 { get; }

        public ImageSource ImageSource { get;}

        public Color BackgroundColor { get; }

        #endregion

        #region Constructors

        public ContactBinding(Contact contact, bool isApproved, string imageBase64 = null)
        {
            Contact = contact;
            ImageBase64 = imageBase64;
            IsApproved = isApproved;

            if (!IsApproved)
                BackgroundColor = Color.FromHex("#321565c0");

            if(!string.IsNullOrEmpty(ImageBase64))
                ImageSource = ImageSource.FromStream(() => new MemoryStream(Convert.FromBase64String(ImageBase64)));
            else if (!string.IsNullOrEmpty(Contact.ImagePath))
                ImageSource = ChiotaConstants.IpfsHashGateway + contact.ImagePath;
            else
                ImageSource = ImageSource.FromFile("account.png");
        }

        #endregion
    }
}
