using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;
using Android.Widget;
using Chiota.Models.BackUp;
using Chiota.ViewModels.Classes;
using Xamarin.Forms;

namespace Chiota.ViewModels.BackUp
{
    public class QrCodeViewModel : BaseViewModel
    {
        #region Attributes

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

            //Set a new generated seed.
            Seed = data as string;
        }

        #endregion

        #region Commands

        #region Continue

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PopAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
