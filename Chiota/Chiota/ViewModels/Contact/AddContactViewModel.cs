using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.AddContact;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views.Authentication;
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

        #region Commands

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
                            await PushLoadingSpinnerAsync("Adding Contact");

                            var addContactInteractor = DependencyResolver.Resolve<IUsecaseInteractor<AddContactRequest, AddContactResponse>>();
                            var response = await addContactInteractor.ExecuteAsync(
                                new AddContactRequest
                                {
                                    Name = UserService.CurrentUser.Name,
                                    ImageHash = UserService.CurrentUser.ImageHash,
                                    RequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                                    PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                                    ContactAddress = new Address(ContactAddress)
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
                                case ResponseCode.AmbiguousContactInformation:
                                    await DisplayAlertAsync("Error", "It seems like the provided address is not a valid contact address.");
                                    break;
                                default:
                                    await DisplayAlertAsync("Error", "Something seems to be broken. Please try again later.");
                                    break;
                            }

                            return;
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
