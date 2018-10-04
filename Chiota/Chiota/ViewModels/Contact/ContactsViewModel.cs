using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views.Chat;
using Chiota.Views.Contact;
using Tangle.Net.Entity;
using Xamarin.Forms;

namespace Chiota.ViewModels.Contact
{
    public class ContactsViewModel : BaseViewModel
    {
        #region Attributes

        private List<ContactBinding> _contactList;
        private bool _isVisible;

        #endregion

        #region Properties

        public List<ContactBinding> ContactList
        {
            get => _contactList;
            set
            {
                _contactList = value;
                OnPropertyChanged(nameof(ContactList));
            }
        }

        #endregion

        #region Constructors

        public ContactsViewModel()
        {
            _contactList = new List<ContactBinding>();
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            UpdateView();
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            _isVisible = true;
            Device.StartTimer(TimeSpan.FromSeconds(1), UpdateView);
        }

        #endregion

        #region ViewIsDisappearing

        protected override void ViewIsDisappearing()
        {
            base.ViewIsDisappearing();

            _isVisible = false;
        }

        #endregion

        #region Methods

        #region UpdateView

        private bool UpdateView()
        {
            Device.BeginInvokeOnMainThread(async () =>
            {
                var contacts = await GetContactListAsync();
                var changed = IsContactListChanged(contacts);
                if (changed)
                    ContactList = contacts;
            });

            return _isVisible;
        }

        #endregion

        #region IsContactListChanged

        private bool IsContactListChanged(List<ContactBinding> contacts)
        {
            if (ContactList == null || ContactList.Count != contacts.Count)
                return true;

            var currentPending = ContactList.FindAll(t => !t.IsApproved);
            var currentApproved = ContactList.FindAll(t => t.IsApproved);

            var pending = contacts.FindAll(t => !t.IsApproved);
            var approved = contacts.FindAll(t => t.IsApproved);

            if (currentPending.Count != pending.Count || currentApproved.Count != approved.Count)
                return true;

            return false;
        }

        #endregion

        #region GetContactList

        private async Task<List<ContactBinding>> GetContactListAsync()
        {
            var tmp = new List<ContactBinding>();

            var interactor = DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>();
            var response = await interactor.ExecuteAsync(new GetContactsRequest()
            {
                ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

            if (response.Code == ResponseCode.Success)
            {
                foreach (var pending in response.PendingContactRequests)
                    tmp.Add(new ContactBinding(pending, false, TapContactRequestCommand));

                foreach (var approved in response.ApprovedContacts)
                    tmp.Add(new ContactBinding(approved, true, TapContactCommand));
            }

            //TODO Maybe, we need to sort the contacts alphabetical.

            return tmp;
        }

        #endregion

        #endregion

        #region Commands

        #region TapContactRequest

        public ICommand TapContactRequestCommand
        {
            get
            {
                return new Command(async(param) =>
                {
                    if (param is ContactBinding contact)
                        await PushAsync<ContactRequestView>(contact.Contact);
                    else
                        await new UnknownException(new ExcInfo()).ShowAlertAsync();
                });
            }
        }

        #endregion

        #region TapContact

        public ICommand TapContactCommand
        {
            get
            {
                return new Command(async (param) =>
                {
                    if (param is ContactBinding contact)
                        await PushAsync<ChatView>(contact.Contact);
                    else
                        await new UnknownException(new ExcInfo()).ShowAlertAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
