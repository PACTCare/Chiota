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

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);
            UserProperties = data as UserCreationProperties;
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            Seed = string.Empty;
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