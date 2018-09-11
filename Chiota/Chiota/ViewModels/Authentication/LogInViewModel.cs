using System.Windows.Input;

using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Pages.Authentication;
using Chiota.Pages.Help;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views;

using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
  using System;

  using Chiota.Annotations;

  /// <summary>
    /// The log in view model.
    /// </summary>
    public class LogInViewModel : BaseViewModel
    {
        #region Attributes

        private string password;

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

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            this.Password = string.Empty;
        }

        #endregion

        #region Commands

        #region LogIn

        /// <summary>
        /// Gets the log in command.
        /// </summary>
        public ICommand LogInCommand
        {
            get
            {
                return new Command(async () =>
                    {
                        try
                        {
                            await this.DisplayLoadingSpinnerAsync("Logging you in ...");

                            await SecureStorage.LoginUser(this.Password);
                            Application.Current.MainPage = new NavigationPage(new ContactPage());

                            await this.PopPopupAsync();
                        }
                        catch (BaseException exception)
                        {
                            await this.PopPopupAsync();
                            await exception.ShowAlertAsync();
                        }
                    });
            }
        }

        #endregion

        #region NewSeed

        public ICommand NewSeedCommand => new Command(async () => { await this.PushAsync(new NewSeedPage()); });

        #endregion

        #region SetSeed

        public ICommand SetSeedCommand => new Command(async () => { await this.PushAsync(new SetSeedPage()); });

        #endregion

        #region SeedHelp

        public ICommand SeedHelpCommand => new Command(async () => { await this.PushAsync(new SeedHelpPage()); });

    #endregion

      [UsedImplicitly]
      public ICommand PrivacyCommand => new Command(() => { Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md")); });

    #endregion
  }
}