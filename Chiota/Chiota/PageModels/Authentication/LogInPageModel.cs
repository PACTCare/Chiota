using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.PageModels.Classes;
using Chiota.Pages.Authentication;
using Tangle.Net.Utils;
using Xamarin.Forms;
using ZXing.Net.Mobile.Forms;

namespace Chiota.PageModels.Authentication
{
    public class LogInPageModel : BasePageModel
    {
        #region Attributes

        private string _password;

        #endregion

        #region Properties

        public string Password
        {
            get => _password;
            set
            {
                _password = value;
                OnPropertyChanged(nameof(Password));
            }
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            //Clear the user inputs.
            Password = "";
        }

        #endregion

        #region Commands

        #region LogIn

        public ICommand LogInCommand
        {
            get
            {
                return new Command(async () =>
                {
                    if (!string.IsNullOrEmpty(Password))
                    {
                        //TODO Get the current user of the database and check, if the input is the password.
                        return;
                    }

                    //Missing password user input.
                    await new MissingUserInputException(new ExcInfo(), "password").ShowAlertAsync();
                });
            }
        }

        #endregion

        #region SetSeed

        public ICommand SetSeedCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new SetSeedPage());
                });
            }
        }

        #endregion

        #region ChangeSeed

        public ICommand ChangeSeedCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new RegisterPage(), false);
                });
            }
        }

        #endregion

        #endregion
    }
}
