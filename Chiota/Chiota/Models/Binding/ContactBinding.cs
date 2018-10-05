using Chiota.Helper;
using Chiota.Messenger.Entity;
using Chiota.Models.Base;
using Xamarin.Forms;

namespace Chiota.Models.Binding
{
    public class ContactBinding : BaseModel
    {
        #region Properties

        public Contact Contact { get; }

        public bool IsApproved { get; }

        public bool IsNotApproved { get; }

        public ImageSource ImageSource { get;}

        public Color BackgroundColor { get; }

        #endregion

        #region Constructors

        public ContactBinding(Contact contact, bool isApproved)
        {
            Contact = contact;
            IsApproved = isApproved;
            IsNotApproved = !isApproved;

            if (!IsApproved)
                BackgroundColor = Color.FromHex("#321565c0");

            if(string.IsNullOrEmpty(contact.ImageHash))
                ImageSource = ImageSource.FromFile("account.png");
            else
                ImageSource = ChiotaConstants.IpfsHashGateway + contact.ImageHash;
        }

        #endregion
    }
}
