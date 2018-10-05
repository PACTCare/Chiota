using System.Windows.Input;

using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Tangle.Net.Entity;
using Tangle.Net.Utils;

using Xamarin.Forms;

using ZXing.Net.Mobile.Forms;

namespace Chiota.ViewModels.Authentication
{
  using Chiota.Views.Authentication;

  public class SetSeedViewModel : BaseViewModel
    {
        #region Attributes

        private string seed;

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

                            await PushAsync<SetPasswordView>(new UserCreationProperties { Seed = new Seed(Seed) });
                            return;
                        }

                        await new MissingUserInputException(new ExcInfo(), Details.AuthMissingSeed).ShowAlertAsync();
                    });
            }
        }

        #endregion

        #endregion
    }
}