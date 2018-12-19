#region References

using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Popups.Base;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupViews;
using Chiota.Resources.Localizations;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.AddContact;
using Tangle.Net.Entity;
using Tangle.Net.Utils;
using Xamarin.Forms;
using ZXing.Net.Mobile.Forms;

#endregion

namespace Chiota.Popups.PopupViewModels
{
    public class AddContactPopupViewModel : BasePopupViewModel<AddContactPopupModel>
    {
        #region Attributes

        private bool _isVisible;
        private Keyboard _keyboard;
        private ImageSource _validationImageSource;

        #endregion

        #region Properties

        public bool IsVisible
        {
            get => _isVisible;
            set
            {
                _isVisible = value;
                OnPropertyChanged(nameof(IsVisible));
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

        public ImageSource ValidationImageSource
        {
            get => _validationImageSource;
            set
            {
                _validationImageSource = value;
                OnPropertyChanged(nameof(ValidationImageSource));
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="AddContactPopupViewModel"/> class.
        /// </summary>
        public AddContactPopupViewModel() : base()
        {
            //Create an instance of the popup model.
            PopupModel = new AddContactPopupModel();
            IsVisible = true;
        }

        public AddContactPopupViewModel(AddContactPopupModel popupModel) : base(popupModel)
        {
            IsVisible = true;
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
                        ValidationImageSource = ImageSource.FromFile("done_white.png");
                    else if (!string.IsNullOrEmpty(PopupModel.Address))
                        ValidationImageSource = ImageSource.FromFile("clear.png");
                    else
                        ValidationImageSource = null;
                });
            }
        }

        #endregion

        #region QrCode

        public ICommand QrCodeCommand
        {
            get
            {
                return new Command(async (param) =>
                {
                    // Scan a qr code and insert the result into the entry.
                    var scanPage = new ZXingScannerPage();
                    scanPage.OnScanResult += (result) =>
                    {
                        scanPage.IsScanning = false;

                        Device.BeginInvokeOnMainThread(() =>
                        {
                            Navigation.PopAsync();
                            IsVisible = true;
                            PopupModel.Address = result.Text;
                        });
                    };

                    //Open the scanner page.
                    IsVisible = false;
                    await Page.Navigation.PushAsync(scanPage);
                });
            }
        }

        #endregion

        #region Pos

        /// <summary>
        /// Ok method of the popup.
        /// </summary>
        public ICommand PosCommand
        {
            get
            {
                return new Command( async () =>
                {
                    if (!string.IsNullOrEmpty(PopupModel.Address))
                    {
                        if (!InputValidator.IsAddress(PopupModel.Address) || PopupModel.Address == UserService.CurrentUser.PublicKeyAddress)
                        {
                            await new InvalidUserInputException(new ExcInfo(), Details.ContactInvalidUserInputContactAddress).ShowAlertAsync();
                            return;
                        }

                        //Start contact request of the user.
                        if (InputValidator.IsAddress(PopupModel.Address) && PopupModel.Address != UserService.CurrentUser.PublicKeyAddress)
                        {
                            try
                            {
                                IsVisible = false;
                                await PushPopupAsync<LoadingPopupViewModel, LoadingPopupModel>(new LoadingPopupView(), new LoadingPopupModel { Message = AppResources.DlgAddContact });

                                var addContactInteractor = DependencyResolver.Resolve<IUsecaseInteractor<AddContactRequest, AddContactResponse>>();
                                var response = await addContactInteractor.ExecuteAsync(
                                    new AddContactRequest
                                    {
                                        Name = UserService.CurrentUser.Name,
                                        ImagePath = UserService.CurrentUser.ImagePath,
                                        ContactAddress = new Address(PopupModel.Address),
                                        RequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                                        PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                                        UserPublicKey = UserService.CurrentUser.NtruKeyPair.PublicKey
                                    });

                                //await PopPopupAsync();
                                await PopPopupAsync();

                                switch (response.Code)
                                {
                                    case ResponseCode.Success:
                                        await DisplayPopupAsync<AlertPopupViewModel, AlertPopupModel>(new AlertPopupView(), new AlertPopupModel(){Title = "Successful Request", Message = "Your new contact needs to accept the request before you can start chatting!" });
                                        break;
                                    case ResponseCode.MessengerException:
                                        await DisplayPopupAsync<AlertPopupViewModel, AlertPopupModel>(new AlertPopupView(), new AlertPopupModel() { Title = "Error", Message = "It seems like the connection to the tangle failed. Try again later or change your node." });
                                        break;
                                    default:
                                        await DisplayPopupAsync<AlertPopupViewModel, AlertPopupModel>(new AlertPopupView(), new AlertPopupModel() { Title = "Error", Message = "Something seems to be broken. Please try again later." });
                                        break;
                                }

                                Finish = true;
                                return;
                            }
                            catch (Exception ex)
                            {
                                await PopPopupAsync();
                                await PopPopupAsync();
                                await new UnknownException(new ExcInfo()).ShowAlertAsync();

                                Finish = true;
                                return;
                            }
                        }
                    }

                    await new MissingUserInputException(new ExcInfo(), Details.ContactMissingContactAddress).ShowAlertAsync();

                    Finish = true;
                    await PopPopupAsync();
                });
            }
        }

        #endregion

        #region Neg

        /// <summary>
        /// Cancel method of the popup
        /// </summary>
        public ICommand NegCommand
        {
            get
            {
                return new Command( async () =>
                    {
                        Finish = true;
                        await PopPopupAsync();
                    });
            }
        }

        #endregion

        #endregion
    }
}
