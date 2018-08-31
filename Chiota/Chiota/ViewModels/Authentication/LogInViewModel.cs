using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.ViewModels.Classes;
using Chiota.Pages.Authentication;
using Chiota.Pages.Help;
using Tangle.Net.Utils;
using Xamarin.Forms;
using ZXing.Net.Mobile.Forms;

namespace Chiota.ViewModels.Authentication
{
    public class LogInViewModel : BaseViewModel
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
                    //Check password.
                    if (false)
                    {
                        //TODO Navigate to contact page.
                        //await PushAsync(new SetUserPage());
                        return;
                    }

                    await new InvalidUserInputException(new ExcInfo(), Details.AuthInvalidUserInputPassword).ShowAlertAsync();
                });
            }
        }

        #endregion

        #region NewSeed

        public ICommand NewSeedCommand
        {
            get
            {
                return new Command(async () =>
                {
                    //Show register page.
                    await PushAsync(new NewSeedPage());
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

        #region SeedHelp

        public ICommand SeedHelpCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new SeedHelpPage());
                });
            }
        }

        #endregion

        #endregion
    }
}
