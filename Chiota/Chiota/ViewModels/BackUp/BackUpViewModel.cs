using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.ViewModels.Classes;
using Chiota.Pages.BackUp;
using Xamarin.Forms;

namespace Chiota.ViewModels.BackUp
{
    public class BackUpViewModel : BaseViewModel
    {
        #region Attributes

        private string _seed;
        private bool _isContinueVisible;

        #endregion

        #region Properties

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

        #region Methods

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            //Set the generated iota seed.
            if(data != null)
                _seed = data as string;

            //Disable the continue button.
            IsContinueVisible = false;
        }

        #endregion

        #region Reverse

        public override void Reverse(object data = null)
        {
            base.Reverse(data);

            //Enable the continue button.
            IsContinueVisible = true;
        }

        #endregion

        #endregion

        #region Commands

        #region WriteSeed

        public ICommand WriteSeedCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new WriteSeedPage(), _seed);
                });
            }
        }

        #endregion

        #region PrintPaper

        public ICommand PrintPaperCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new PaperCopyPage(), _seed);
                });
            }
        }

        #endregion

        #region QrCode

        public ICommand QrCodeCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new QrCodePage(), _seed);
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
                    await PushAsync(new ConfirmSeedPage(), _seed);
                });
            }
        }

        #endregion

        #endregion
    }
}
