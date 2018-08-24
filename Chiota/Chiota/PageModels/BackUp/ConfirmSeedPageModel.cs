using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.PageModels.Classes;
using Chiota.Pages.BackUp;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupPageModels;
using Chiota.Popups.PopupPages;
using Chiota.Views;
using Tangle.Net.Utils;
using Xamarin.Forms;
using ZXing.Net.Mobile.Forms;

namespace Chiota.PageModels.BackUp
{
    public class ConfirmSeedPageModel : BasePageModel
    {
        #region Attributes

        private string _expectedSeed;
        private string _seed;

        #endregion

        #region Properties

        public string Seed
        {
            get => _seed;
            set
            {
                _seed = value;
                OnPropertyChanged(nameof(Seed));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            _expectedSeed = data as string;
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            //Clear the user inputs.
            Seed = "";
        }

        #endregion

        #region Commands

        #region ScanQrCode

        public ICommand ScanQrCodeCommand
        {
            get
            {
                return new Command(async() =>
                {
                    //Scan a qr code and insert the result into the entry.
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

                    await PushAsync(scanPage);
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
                            await new InvalidUserInputException(new ExcInfo(), "seed").ShowAlertAsync();
                            return;
                        }

                        if (Seed != _expectedSeed)
                        {
                            await new BackUpFailedSeedConfirmationException(new ExcInfo()).ShowAlertAsync();
                            return;
                        }

                        //TODO Navigate to the contact page.
                        //await PushAsync(new ContactPage());
                        return;
                    }

                    await new MissingUserInputException(new ExcInfo(), "seed").ShowAlertAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
