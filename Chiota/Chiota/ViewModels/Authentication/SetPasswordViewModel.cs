using System.Windows.Input;

using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;

using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
  using Chiota.Views.Authentication;

  public class SetPasswordViewModel : BaseViewModel
    {
        #region Attributes

        private string password;
        private string repeatPassword;

        private UserCreationProperties UserProperties;

        #endregion

        #region Properties

        public string Password
        {
            get => this.password;
            set
            {
                this.password = value;
                this.OnPropertyChanged(nameof(this.Password));
            }
        }

        public string RepeatPassword
        {
            get => this.repeatPassword;
            set
            {
                this.repeatPassword = value;
                this.OnPropertyChanged(nameof(this.RepeatPassword));
            }
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);
            this.UserProperties = data as UserCreationProperties;
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            this.Password = string.Empty;
            this.RepeatPassword = string.Empty;
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
                        if (string.IsNullOrEmpty(this.Password) || string.IsNullOrEmpty(this.RepeatPassword))
                        {
                            await new MissingUserInputException(new ExcInfo(), Details.AuthMissingUserInputPasswordRepeat).ShowAlertAsync();
                        }
                        else if (this.Password != this.RepeatPassword)
                        {
                            await new AuthFailedPasswordConfirmationException(new ExcInfo()).ShowAlertAsync();
                            return;
                        }

                        this.UserProperties.Password = this.Password;
                        await this.PushAsync(new SetUserView(), this.UserProperties);
                    });
            }
        }

        #endregion
    }
}