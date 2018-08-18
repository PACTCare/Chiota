using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.PageModels.Classes;
using Chiota.Pages.Authentication;
using Xamarin.Forms;

namespace Chiota.PageModels.Authentication
{
    public class WelcomePageModel : BasePageModel
    {
        #region Commands

        #region Register

        public ICommand RegisterCommand
        {
            get
            {
                return new Command(async () =>
                {
                    //Show register page.
                    await PushAsync(new RegisterPage());
                });
            }
        }

        #endregion

        #region SetSeed

        public ICommand SetSeedCommand
        {
            get
            {
                return new Command(() =>
                {
                    //Not implemented
                });
            }
        }

        #endregion

        #endregion
    }
}
