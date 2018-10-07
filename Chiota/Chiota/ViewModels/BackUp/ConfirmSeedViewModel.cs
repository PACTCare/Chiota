using System;
using System.Threading.Tasks;
using System.Windows.Input;

using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Tangle.Net.Utils;

using Xamarin.Forms;

using ZXing.Net.Mobile.Forms;

namespace Chiota.ViewModels.BackUp
{
  using Chiota.Views.Authentication;

  public class ConfirmSeedViewModel : BaseViewModel
    {
        #region Attributes

        private string seed;
        private bool _isEntryFocused;
        private ImageSource _validationImageSource;
        private Keyboard _keyboard;

        private UserCreationProperties UserProperties;

        #endregion

        #region Properties

        public string Seed
        {
            get => seed;
            set
            {
                seed = value;
                OnPropertyChanged(nameof(Seed));
            }
        }

        public bool IsEntryFocused
        {
            get => _isEntryFocused;
            set
            {
                _isEntryFocused = value;
                OnPropertyChanged(nameof(IsEntryFocused));
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

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);
            UserProperties = data as UserCreationProperties;

            Keyboard = Keyboard.Create(KeyboardFlags.CapitalizeCharacter);
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            Seed = string.Empty;

            Device.BeginInvokeOnMainThread(async () =>
            {
                //Focus the entry.
                await Task.Delay(TimeSpan.FromMilliseconds(500));
                IsEntryFocused = true;
            });
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
                    else if (!string.IsNullOrEmpty(Seed))
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
                            Seed = result.Text;

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
                    if (!string.IsNullOrEmpty(Seed))
                    {
                        if (!InputValidator.IsTrytes(Seed))
                        {
                            await new InvalidUserInputException(new ExcInfo(), Details.BackUpInvalidUserInputSeed).ShowAlertAsync();
                            return;
                        }

                        if (Seed != UserProperties.Seed.Value)
                        {
                            await new BackUpFailedSeedConfirmationException(new ExcInfo()).ShowAlertAsync();
                            return;
                        }

                        await PushAsync<SetPasswordView>(UserProperties);
                        return;
                    }

                    await new MissingUserInputException(new ExcInfo(), Details.BackUpInvalidUserInputSeed).ShowAlertAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}