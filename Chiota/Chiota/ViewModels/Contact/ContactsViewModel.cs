using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Models;
using Chiota.Models.Binding;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
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
        private bool _isUpdating;

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

            _isUpdating = true;
            Device.StartTimer(TimeSpan.FromSeconds(1), UpdateView);
        }

        #endregion

        #region ViewIsDisappearing

        protected override void ViewIsDisappearing()
        {
            base.ViewIsDisappearing();

            _isUpdating = false;
        }

        #endregion

        #region Methods

        #region UpdateView

        private bool UpdateView()
        {
            /*Device.BeginInvokeOnMainThread(async () =>
            {
                var contacts = await GetContactListAsync();
                var changed = IsContactListChanged(contacts);
                if (changed)
                    ContactList = contacts;
            });*/

            return _isUpdating;
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
                    tmp.Add(new ContactBinding(pending, false));

                foreach (var approved in response.ApprovedContacts)
                    tmp.Add(new ContactBinding(approved, true));
            }

            //TODO Maybe, we need to sort the contacts alphabetical.

            return tmp;
        }

        #endregion

        #endregion

        #region Commands

        #region Tap

        public ICommand TapCommand
        {
            get
            {
                return new Command(async (param) =>
                {
                    if (!(param is ContactBinding contact))
                    {
                        //Show an unknown exception.
                        await new UnknownException(new ExcInfo()).ShowAlertAsync();
                        return;
                    }

                    //Show the chat view, or a dialog for a contact request acceptation.
                    if (contact.IsApproved)
                        await PushAsync<ChatView>(contact.Contact);
                    else
                        await PushAsync<ContactRequestView>(contact.Contact);
                });
            }
        }

        #endregion

        #endregion
    }
}
