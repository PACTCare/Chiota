using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Resources.Localizations;
using Chiota.Services;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Xamarin.Forms;

namespace Chiota.ViewModels.Contact
{
    public class ContactAddressViewModel : BaseViewModel
    {
        #region Attributes

        private string _contactAddress;

        #endregion

        #region Properties

        public string ContactAddress
        {
            get => _contactAddress;
            set
            {
                _contactAddress = value;
                OnPropertyChanged(nameof(ContactAddress));
            }
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);

            ContactAddress = UserService.CurrentUser.PublicKeyAddress;
        }

        #endregion

        #region Commands

        #region TapQrCode

        public ICommand TapQrCodeCommand
        {
            get
            {
                return new Command(async () =>
                {
                    DependencyResolver.Resolve<IClipboardService>().SendTextToClipboard(ContactAddress);
                    await DisplayAlertAsync("Address copied", "The address has been copied to your clipboard");
                });
            }
        }

        #endregion

        #endregion
    }
}
