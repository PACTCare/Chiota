#region References

using Chiota.Popups.Base;
using Tangle.Net.Entity;

#endregion

namespace Chiota.Popups.PopupModels
{
    public class AddContactPopupModel : BasePopupModel
    {
        #region Attributes

        private string _address;

        #endregion

        #region Properties

        public string Address
        {
            get => _address;
            set
            {
                _address = value;
                OnPropertyChanged(nameof(Address));
            }
        }

        #endregion
    }
}
