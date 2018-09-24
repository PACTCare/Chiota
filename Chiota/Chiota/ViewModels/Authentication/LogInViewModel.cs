using System.Windows.Input;
using Chiota.Classes;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views;

using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
  using System;

  using Chiota.Annotations;
  using Chiota.Views.Authentication;
  using Chiota.Views.Help;

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
            get => password;
            set
            {
                password = value;
                OnPropertyChanged(nameof(Password));
            }
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            Password = string.Empty;
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
                            await PushLoadingSpinnerAsync("Logging you in ...");

                            await SecureStorage.LoginUser(Password);
                            await PopPopupAsync();

                            AppNavigation.ShowMessenger();
                        }
                        catch (BaseException exception)
                        {
                            await PopPopupAsync();
                            await exception.ShowAlertAsync();
                        }
                    });
            }
        }

        #endregion

        #region NewSeed

        public ICommand NewSeedCommand => new Command(async () => { await PushAsync<NewSeedView>(); });

        #endregion

        #region SetSeed

        public ICommand SetSeedCommand => new Command(async () => { await PushAsync<SetSeedView>(); });

        #endregion

        #region SeedHelp

        public ICommand SeedHelpCommand => new Command(async () => { await PushAsync<SeedHelpView>(); });

    #endregion

      [UsedImplicitly]
      public ICommand PrivacyCommand => new Command(() => { Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md")); });

    #endregion
  }
}