using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Resources.Localizations;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
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
        private bool _isEntryFocused;
        private bool _started;

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

        public bool IsEntryFocused
        {
            get => _isEntryFocused;
            set
            {
                _isEntryFocused = value;
                OnPropertyChanged(nameof(IsEntryFocused));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            if (data == null) return;
            _started = (bool)data;
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            Password = string.Empty;

            if (_started)
            {
                Device.BeginInvokeOnMainThread(async () =>
                {
                    //Focus the entry.
                    await Task.Delay(TimeSpan.FromMilliseconds(500));
                    IsEntryFocused = true;
                });
            }
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
                            await PushLoadingSpinnerAsync(AppResources.DlgLoggingIn);

                            var userService = DependencyResolver.Resolve<UserService>();
                            var result = await userService.LogInAsync(Password);

                            await PopPopupAsync();

                            if (!result)
                            {
                                await new InvalidUserInputException(new ExcInfo(), Details.AuthInvalidUserInputPassword).ShowAlertAsync();
                                return;
                            }

                            AppBase.ShowMessenger();
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

        #region SeedHelp

        public ICommand SeedHelpCommand => new Command(async () => { await PushAsync<SeedHelpView>(); });

    #endregion

      [UsedImplicitly]
      public ICommand PrivacyCommand => new Command(() => { Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md")); });

    #endregion
  }
}