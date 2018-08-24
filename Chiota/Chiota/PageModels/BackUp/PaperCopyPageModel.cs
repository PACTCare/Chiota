using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Models.BackUp;
using Chiota.PageModels.Classes;
using Xamarin.Forms;

namespace Chiota.PageModels.BackUp
{
    public class PaperCopyPageModel : BasePageModel
    {
        #region Attributes

        private Seed _seed;
        private bool _isContinueVisible;

        #endregion

        #region Properties

        public Seed Seed
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
            Seed = new Seed(data as string);
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
