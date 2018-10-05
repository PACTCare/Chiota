using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Helper;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.AcceptContact;
using Chiota.Messenger.Usecase.DeclineContact;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Tangle.Net.Entity;
using Xamarin.Forms;

namespace Chiota.ViewModels.Contact
{
    public class ContactRequestViewModel : BaseViewModel
    {
        #region Attributes

        private string _username;
        private ImageSource _profileImageSource;

        private Chiota.Messenger.Entity.Contact _contact;

        #endregion

        #region Properties

        public string Username
        {
            get => _username;
            set
            {
                _username = value;
                OnPropertyChanged(nameof(Username));
            }
        }

        public ImageSource ProfileImageSource
        {
            get => _profileImageSource;
            set
            {
                _profileImageSource = value;
                OnPropertyChanged(nameof(ProfileImageSource));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            _contact = data as Chiota.Messenger.Entity.Contact;
            if(_contact == null)
            {
                Device.BeginInvokeOnMainThread(async () =>
                {
                    await new UnknownException(new ExcInfo()).ShowAlertAsync();
                    await PopAsync();
                });
                return;
            }

            Username = _contact.Name;

            if(_contact.ImageHash != null)
                ProfileImageSource = ImageSource.FromUri(new Uri(ChiotaConstants.IpfsHashGateway + _contact.ImageHash));
            else
                ProfileImageSource = ImageSource.FromFile("account.png");
        }

        #endregion

        #region Commands

        #region Accept

        public ICommand AcceptCommand
        {
            get
            {
                return new Command(async() =>
                {
                    await PushLoadingSpinnerAsync("Accepting contact");

                    var acceptContactInteractor = DependencyResolver.Resolve<IUsecaseInteractor<AcceptContactRequest, AcceptContactResponse>>();

                    var response = await acceptContactInteractor.ExecuteAsync(new AcceptContactRequest{
                        UserName = UserService.CurrentUser.Name,
                        UserImageHash = UserService.CurrentUser.ImageHash,
                        ChatAddress = new Address(_contact.ChatAddress),
                        ChatKeyAddress = new Address(_contact.ChatKeyAddress),
                        ContactAddress = new Address(_contact.ContactAddress),
                        ContactPublicKeyAddress = new Address(_contact.PublicKeyAddress),
                        UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                        UserKeyPair = UserService.CurrentUser.NtruKeyPair
                    });

                    await PopPopupAsync();

                    if (response.Code == ResponseCode.Success)
                    {
                        await DisplayAlertAsync("Successful action", "The contact was successfully added.");
                        await PopAsync();
                    }
                    else
                        await DisplayAlertAsync("Error", $"An error (Code: {(int)response.Code}) occured while adding the contact.");
                });
            }
        }

        #endregion

        #region Decline

        public ICommand DeclineCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushLoadingSpinnerAsync("Declining contact");

                    var declineContactInteractor = DependencyResolver.Resolve<IUsecaseInteractor<DeclineContactRequest, DeclineContactResponse>>();

                    await declineContactInteractor.ExecuteAsync(new DeclineContactRequest
                    {
                        ContactChatAddress = new Address(_contact.ChatAddress),
                        UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
                    });

                    await PopPopupAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
