using System.Windows.Input;

using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
  using Chiota.Views.Authentication;

  public class SetPasswordViewModel : BaseViewModel
    {
        #region Attributes

        private string password;
        private string repeatPassword;

        private static UserCreationProperties userProperties;

        #endregion

        #region Properties

        public string Password
        {
            get => password;
            set
            {
                password = value;
                OnPropertyChanged(nameof(Password));
            }
        }

        public string RepeatPassword
        {
            get => repeatPassword;
            set
            {
                repeatPassword = value;
                OnPropertyChanged(nameof(RepeatPassword));
            }
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);
            userProperties = data as UserCreationProperties;
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            Password = string.Empty;
            RepeatPassword = string.Empty;
        }

        #endregion

        #region Commands

        /// <summary>
        /// Gets the continue command.
        /// </summary>
        public ICommand ContinueCommand
        {
            get
            {
                return new Command(async () =>
                    {
                        if (string.IsNullOrEmpty(Password) || string.IsNullOrEmpty(RepeatPassword))
                        {
                            await new MissingUserInputException(new ExcInfo(), Details.AuthMissingUserInputPasswordRepeat).ShowAlertAsync();
                        }
                        else if (Password != RepeatPassword)
                        {
                            await new AuthFailedPasswordConfirmationException(new ExcInfo()).ShowAlertAsync();
                            return;
                        }

                        userProperties.Password = Password;
                        await PushAsync<SetUserView>(userProperties);
                    });
            }
        }

        #endregion
    }
}