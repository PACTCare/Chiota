using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Messenger.Usecase.GetMessages;
using Chiota.Resources.Localizations;
using Chiota.Services.Database;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views;
using Tangle.Net.Entity;
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

        #region Methods

        #region LoadUserData

        /// <summary>
        /// Load all user data.
        /// </summary>
        /// <returns></returns>
        private async Task LoadUserDataAsync()
        {
            //Load all accepted contacts.
            var response = await DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>().ExecuteAsync(new GetContactsRequest()
            {
                ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

            if (response.Code == ResponseCode.Success && response.ApprovedContacts.Count > 0)
            {
                //Check, if all the contacts saved in the database and update them, if necessary.
                foreach (var approved in response.ApprovedContacts)
                {
                    var exist = DatabaseService.Contact.GetAcceptedContactByChatAddress(approved.ChatAddress);

                    //Update the contact in the database.
                    if (exist != null)
                    {
                        exist.Name = approved.Name;
                        exist.ChatKeyAddress = approved.ChatKeyAddress;
                        exist.ContactAddress = approved.ContactAddress;
                        exist.ImageHash = approved.ImageHash;

                        //Load the image, if the hash is not empty.
                        if (!string.IsNullOrEmpty(exist.ImageHash))
                        {
                            //exist.ImageBase64
                        }
                            
                        //Update the contact in the database.
                        DatabaseService.Contact.UpdateObject(exist);
                    }
                }


                //Load new messages from of the user.
                /*foreach (var approved in response.ApprovedContacts)
                {
                    var messagesResponse = await DependencyResolver.Resolve<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>().ExecuteAsync(
                        new GetMessagesRequest
                        {
                            ChatAddress = new Address(approved.ChatAddress),
                            ChatKeyPair = null,
                            ChatKeyAddress = new Address(approved.ChatKeyAddress),
                            UserKeyPair = UserService.CurrentUser.NtruKeyPair
                        });
                }*/
            }
        }

        #endregion

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

                            //Update database, if the log in is successfully.
                            if (result)
                                await LoadUserDataAsync();

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

        #region Privacy

        public ICommand PrivacyCommand => new Command(() =>
        {
            Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md"));
        });

        #endregion

        #endregion
    }
}