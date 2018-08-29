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
    public class SetPasswordPageModel : BasePageModel
    {
        #region Attributes

        private string _password;
        private string _repeatPassword;

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

        public string RepeatPassword
        {
            get => _repeatPassword;
            set
            {
                _repeatPassword = value;
                OnPropertyChanged(nameof(RepeatPassword));
            }
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            //Clear the user inputs.
            Password = "";
            RepeatPassword = "";
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
                    if (!string.IsNullOrEmpty(Password) && !string.IsNullOrEmpty(RepeatPassword))
                    {
                        if (Password != RepeatPassword)
                        {
                            await new AuthFailedPasswordConfirmationException(new ExcInfo()).ShowAlertAsync();
                            return;
                        }

                        await PushAsync(new SetUserPage());
                        return;
                    }

                    await new MissingUserInputException(new ExcInfo(), "password or repeat password").ShowAlertAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
