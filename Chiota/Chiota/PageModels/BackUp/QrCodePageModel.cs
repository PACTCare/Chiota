using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Android.Widget;
using Chiota.Models.BackUp;
using Chiota.PageModels.Classes;
using Xamarin.Forms;
using ZXing;
using ZXing.Net.Mobile.Forms;
using ZXing.QrCode;

namespace Chiota.PageModels.BackUp
{
    public class QrCodePageModel : BasePageModel
    {
        #region Attributes

        private bool _isContinueVisible;
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

        public bool IsContinueVisible
        {
            get => _isContinueVisible;
            set
            {
                _isContinueVisible = value;
                OnPropertyChanged(nameof(IsContinueVisible));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            //Set the generated iota seed.
            var seed = data as string;

            //Generate qr code by the seed.
            var qrCode = new ZXingBarcodeImageView
            {
                BarcodeFormat = BarcodeFormat.QR_CODE,
                BarcodeOptions = new QrCodeEncodingOptions
                {
                    Height = 350,
                    Width = 350
                },
                BarcodeValue = seed,
                VerticalOptions = LayoutOptions.CenterAndExpand,
                HorizontalOptions = LayoutOptions.CenterAndExpand,
                WidthRequest = 350,
                HeightRequest = 350
            };
            Seed = seed;
        }

        #endregion

        #region Commands

        #region PrintButton

        public ICommand PrintCommand
        {
            get
            {
                return new Command(async () =>
                {
                    //TODO Direkt printing or print pdf??

                    //Go back to back up page.
                    await PopAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
