using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Resources.Localizations;
using Chiota.Services.BackgroundServices;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Ipfs;
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
        private bool _isEntryFocused;

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

            Device.BeginInvokeOnMainThread(async () =>
            {
                //Focus the entry.
                await Task.Delay(TimeSpan.FromMilliseconds(500));
                IsEntryFocused = true;
            });
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

                        await PushLoadingSpinnerAsync(AppResources.DlgSettingUpAccount);

                        //Send the image to ipfs by base64 string.
                        if(userProperties.ImageBase64 != null)
                            userProperties.ImagePath = await new IpfsHelper().PostStringAsync(userProperties.ImageBase64);

                        var userService = DependencyResolver.Resolve<UserService>();
                        var result = await userService.CreateNew(userProperties);

                        await PopPopupAsync();

                        if (!result)
                        {
                            await new UnknownException(new ExcInfo()).ShowAlertAsync();
                            AppBase.ShowStartUp();
                            return;
                        }

                        try
                        {
                            //Start the background service for receiving notifications of the tangle,
                            //to update the user outside of the app.
                            DependencyService.Get<IBackgroundJobWorker>().Add<ContactRequestBackgroundJob>(UserService.CurrentUser);
                        }
                        catch (Exception ex)
                        {
                            //Ignore
                        }

                        AppBase.ShowMessenger();
                    });
            }
        }

        #endregion
    }
}