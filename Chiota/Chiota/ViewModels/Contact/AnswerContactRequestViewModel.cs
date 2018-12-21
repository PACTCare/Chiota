﻿#region References

using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Helper;
using Chiota.Services.BackgroundServices;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.AcceptContact;
using Pact.Palantir.Usecase.DeclineContact;
using Tangle.Net.Entity;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Contact
{
    public class AnswerContactRequestViewModel : BaseViewModel
    {
        #region Attributes

        private static string _username;
        private static ImageSource _imageSource;

        private Pact.Palantir.Entity.Contact _contact;

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

        public ImageSource ImageSource
        {
            get => _imageSource;
            set
            {
                _imageSource = value;
                OnPropertyChanged(nameof(ImageSource));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            _contact = data as Pact.Palantir.Entity.Contact;
            if (_contact == null)
            {
                Device.BeginInvokeOnMainThread(async () =>
                {
                    await new UnknownException(new ExcInfo()).ShowAlertAsync();
                    await PopAsync();
                });
                return;
            }

            Username = _contact.Name;

            if (_contact.ImagePath != null)
                ImageSource = ImageSource.FromUri(new Uri(ChiotaConstants.IpfsHashGateway + _contact.ImagePath));
            else
                ImageSource = ImageSource.FromFile("account.png");
        }

        #endregion

        #region Methods

        #region AcceptContactRequest

        public void AcceptContactRequest(ResponseCode responseCode)
        {
            Task.Run(async () =>
            {
                await PopPopupAsync();

                if (responseCode == ResponseCode.Success)
                {
                    //Update the contact in the database.
                    var contact = Database.Contact.GetContactByPublicKeyAddress(_contact.PublicKeyAddress);
                    contact.Accepted = true;
                    Database.Contact.UpdateObject(contact);

                    await DisplayAlertAsync("Successful action", "The contact was successfully added.");
                    await PopAsync();
                }
                else
                    await DisplayAlertAsync("Error",
                        $"An error (Code: {(int)responseCode}) occured while adding the contact.");
            });
        }

        #endregion

        #region DeclineContactRequest

        public void DeclineContactRequest(ResponseCode responseCode)
        {
            Task.Run(async () =>
            {
                await PopPopupAsync();

                if (responseCode == ResponseCode.Success)
                {
                    //Update the contact in the database.
                    var contact = Database.Contact.GetContactByPublicKeyAddress(_contact.PublicKeyAddress);
                    Database.Contact.DeleteObject(contact.Id);

                    await DisplayAlertAsync("Successful action", "The contact was successfully declined.");
                    await PopAsync();
                }
                else
                    await DisplayAlertAsync("Error",
                        $"An error (Code: {(int)responseCode}) occured while decline the contact.");
            });
        }

        #endregion

        #endregion

        #region Commands

        #region Accept

        public ICommand AcceptCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushLoadingSpinnerAsync("Accepting contact");

                    DependencyService.Get<IBackgroundJobWorker>().Run<AnswerContactRequestBackgroundJob>(UserService.CurrentUser, _contact, true);

                    MessagingCenter.Subscribe<AnswerContactRequestViewModel, ResponseCode>(this, "AnswerContactRequest", (sender, args) => {

                        //First unsubscribe from the message center.
                        MessagingCenter.Unsubscribe<AnswerContactRequestViewModel, ResponseCode>(this, "AnswerContactRequest");
                        
                        AcceptContactRequest(args);
                    });
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
                    
                    DependencyService.Get<IBackgroundJobWorker>().Run<AnswerContactRequestBackgroundJob>(UserService.CurrentUser, _contact, false);

                    MessagingCenter.Subscribe<AnswerContactRequestViewModel, ResponseCode>(this, "AnswerContactRequest", (sender, args) => {

                        //First unsubscribe from the message center.
                        MessagingCenter.Unsubscribe<AnswerContactRequestViewModel, ResponseCode>(this, "AnswerContactRequest");

                        DeclineContactRequest(args);
                    });
                });
            }
        }

        #endregion

        #endregion
    }
}