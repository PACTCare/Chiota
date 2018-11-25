using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Resources.Localizations;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views.Authentication;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.AddContact;
using Rg.Plugins.Popup.Extensions;
using Tangle.Net.Entity;
using Tangle.Net.Utils;
using Xamarin.Forms;
using ZXing.Net.Mobile.Forms;

namespace Chiota.ViewModels.Contact
{
    public class AddContactViewModel : BaseViewModel
    {
        #region Attributes

        private string _contactAddress;
        private ImageSource _validationImageSource;
        private Keyboard _keyboard;

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

        public ImageSource ValidationImageSource
        {
            get => _validationImageSource;
            set
            {
                _validationImageSource = value;
                OnPropertyChanged(nameof(ValidationImageSource));
            }
        }

        public Keyboard Keyboard
        {
            get => _keyboard;
            set
            {
                _keyboard = value;
                OnPropertyChanged(nameof(Keyboard));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            Keyboard = Keyboard.Create(KeyboardFlags.CapitalizeCharacter);
        }

        #endregion

        #region Commands

        #region IsValid

        public ICommand IsValidCommand
        {
            get
            {
                return new Command((param) =>
                {
                    var isValid = (bool)param;

                    if (isValid)
                        ValidationImageSource = ImageSource.FromFile("done.png");
                    else if (!string.IsNullOrEmpty(ContactAddress))
                        ValidationImageSource = ImageSource.FromFile("clear.png");
                    else
                        ValidationImageSource = null;
                });
            }
        }

        #endregion

        #region ScanQrCode

        public ICommand ScanQrCodeCommand
        {
            get
            {
                return new Command(async () =>
                {
                    // Scan a qr code and insert the result into the entry.
                    var scanPage = new ZXingScannerPage();
                    scanPage.OnScanResult += (result) =>
                    {
                        scanPage.IsScanning = false;

                        Device.BeginInvokeOnMainThread(() =>
                        {
                            Navigation.PopAsync();
                            ContactAddress = result.Text;
                        });
                    };

                    await CurrentPage.Navigation.PushAsync(scanPage);
                });
            }
        }


        #endregion

        #region Continue

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(async () =>
                {
                    if (!string.IsNullOrEmpty(ContactAddress))
                    {
                        if (!InputValidator.IsAddress(ContactAddress) || ContactAddress == UserService.CurrentUser.PublicKeyAddress)
                        {
                            await new InvalidUserInputException(new ExcInfo(), Details.ContactInvalidUserInputContactAddress).ShowAlertAsync();
                            return;
                        }

                        //Start contact request of the user.
                        if (InputValidator.IsAddress(ContactAddress) &&
                            ContactAddress != UserService.CurrentUser.PublicKeyAddress)
                        {
                            

                            try
                            {
                                await PushLoadingSpinnerAsync(AppResources.DlgAddContact);

                                var addContactInteractor = DependencyResolver.Resolve<IUsecaseInteractor<AddContactRequest, AddContactResponse>>();
                                var response = await addContactInteractor.ExecuteAsync(
                                    new AddContactRequest
                                    {
                                        Name = UserService.CurrentUser.Name,
                                        ImagePath = UserService.CurrentUser.ImagePath,
                                        RequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                                        PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                                        ContactAddress = new Address(ContactAddress),
                                        UserPublicKey = UserService.CurrentUser.NtruKeyPair.PublicKey
                                    });

                                await PopPopupAsync();

                                switch (response.Code)
                                {
                                    case ResponseCode.Success:
                                        await DisplayAlertAsync(
                                            "Successful Request",
                                            "Your new contact needs to accept the request before you can start chatting!");
                                        break;
                                    case ResponseCode.MessengerException:
                                        await DisplayAlertAsync("Error", "It seems like the connection to the tangle failed. Try again later or change your node.");
                                        break;
                                    default:
                                        await DisplayAlertAsync("Error", "Something seems to be broken. Please try again later.");
                                        break;
                                }

                                return;
                            }
                            catch (Exception)
                            {
                                await PopPopupAsync();
                                await new UnknownException(new ExcInfo()).ShowAlertAsync();
                                return;
                            }
                        }
                    }

                    await new MissingUserInputException(new ExcInfo(), Details.ContactMissingContactAddress).ShowAlertAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
