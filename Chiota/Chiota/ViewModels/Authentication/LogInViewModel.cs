#region References

using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Resources.Localizations;
using Chiota.Services.Database;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.GetContacts;
using Tangle.Net.Entity;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Authentication
{
    public class LogInViewModel : BaseViewModel
    {
        #region Attributes

        private string password;

        private bool _isEntryFocused;

        private bool _isAlertShown;

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

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            Password = string.Empty;

            Device.BeginInvokeOnMainThread(async () =>
            {
                //Focus the entry.
                await Task.Delay(TimeSpan.FromMilliseconds(500));
                IsEntryFocused = true;
            });
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
                    try
                    {
                        //If there is an alert shown,
                        //the user must answer this, before going on.
                        if (_isAlertShown) return;

                        await PushLoadingSpinnerAsync(AppResources.DlgLoggingIn);

                        var userService = DependencyResolver.Resolve<UserService>();
                        var result = await userService.LogInAsync(Password);

                        await PopPopupAsync();

                        if (!result)
                        {
                            _isAlertShown = true;
                            await new InvalidUserInputException(new ExcInfo(), Details.AuthInvalidUserInputPassword).ShowAlertAsync();
                            _isAlertShown = false;
                            return;
                        }

                        AppBase.ShowMessenger();
                    }
                    catch (BaseException exception)
                    {
                        await PopPopupAsync();

                        _isAlertShown = true;
                        await exception.ShowAlertAsync();
                        _isAlertShown = false;
                    }
                });
            }
        }

        #endregion

        #region Privacy

        public ICommand PrivacyCommand => new Command(() =>
        {
            Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md"));
        });

        #endregion

        #endregion
    }
}