#region References

using System;
using System.IO;
using Chiota.Helper;
using Chiota.Models.Database;
using Chiota.Models.Database.Base;
using Pact.Palantir.Entity;
using Xamarin.Forms;

#endregion

namespace Chiota.Models.Binding
{
    public class ContactBinding : BaseModel
    {
        #region Properties

        public DbContact Contact { get; }

        public ImageSource ImageSource { get;}

        public Color BackgroundColor { get; }

        #endregion

        #region Constructors

        public ContactBinding(DbContact contact)
        {
            Contact = contact;

            if (!Contact.Accepted)
                BackgroundColor = Color.FromHex("#321565c0");

            if(!string.IsNullOrEmpty(Contact.ImageBase64))
                ImageSource = ImageSource.FromStream(() => new MemoryStream(Convert.FromBase64String(Contact.ImageBase64)));
            /*else if (!string.IsNullOrEmpty(Contact.ImagePath))
                ImageSource = ChiotaConstants.IpfsHashGateway + contact.ImagePath;*/
            else
                ImageSource = null;
        }

        #endregion
    }
}
