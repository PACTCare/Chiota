using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.PageModels.Classes;
using Xamarin.Forms;

namespace Chiota.PageModels.Help
{
    public class SeedHelpPageModel : BasePageModel
    {
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
