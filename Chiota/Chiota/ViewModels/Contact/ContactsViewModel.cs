using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Models;
using Chiota.Models.Binding;
using Chiota.Services.Database;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views.Chat;
using Chiota.Views.Contact;
using Tangle.Net.Entity;
using Xamarin.Essentials;
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

            //Load all contacts.
            ContactList = LoadContactListByDb();
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            _isUpdating = true;
            Device.StartTimer(TimeSpan.FromSeconds(3), UpdateView);
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

        /// <summary>
        /// Update the view with all contacts.
        /// </summary>
        /// <returns></returns>
        private bool UpdateView()
        {
            Device.BeginInvokeOnMainThread(async () =>
            {
                if (Connectivity.NetworkAccess != NetworkAccess.Internet) return;

                //var dbContacts = LoadContactListByDb();
                var requestContacts = await RequestContactListAsync();

                //Return, if there are no contacts available.
                if (requestContacts == null || requestContacts.Count == 0) return;

                //Get the combined contact list of the request and local database.
                //(Means update the database, if necessary and return the updated contact list.)
                var combinedContacts = GetCombinedContactList(requestContacts);
                if (combinedContacts != null)
                    ContactList = combinedContacts;
            });

            return _isUpdating;
        }

        #endregion

        #region GetContacts

        #region GetCombinedContactList

        private List<ContactBinding> GetCombinedContactList(List<ContactBinding> contacts)
        {
            var combined = new List<ContactBinding>();

            //Load the contacts of the database.
            var dbContacts = LoadContactListByDb();

            /*if (ContactList == null || ContactList.Count != contacts.Count)
                return true;

            var currentPending = ContactList.FindAll(t => !t.IsApproved);
            var currentApproved = ContactList.FindAll(t => t.IsApproved);

            var pending = contacts.FindAll(t => !t.IsApproved);
            var approved = contacts.FindAll(t => t.IsApproved);

            if (currentPending.Count != pending.Count || currentApproved.Count != approved.Count)
                return true;

            return false;*/

            //Return the contact list, if the update is successfully, otherwise return null.
            if (combined.Count > 0)
                return combined;

            return null;
        }

        #endregion

        #region LoadContactListByDb

        /// <summary>
        /// Load the contact list from the local database.
        /// </summary>
        /// <returns></returns>
        private List<ContactBinding> LoadContactListByDb()
        {
            var list = new List<ContactBinding>();

            try
            {
                var contacts = DatabaseService.Contact.GetContactsOrderByAcceptedDesc();
                foreach (var item in contacts)
                {
                    var exist = list.Any(t => t.Contact.ChatAddress == item.ChatAddress);
                    if (!exist)
                    {
                        var contact = new Messenger.Entity.Contact()
                        {
                            ChatAddress = item.ChatAddress,
                            Name = item.Name,
                            ImageHash = item.ImageHash,
                            ChatKeyAddress = item.ChatKeyAddress,
                            PublicKeyAddress = item.PublicKeyAddress,
                            Rejected = !item.Accepted
                        };
                        list.Add(new ContactBinding(contact, item.Accepted, item.ImageBase64));
                    }
                }
            }
            catch (Exception)
            {

            }

            return list;
        }

        #endregion

        #region RequestContactList

        /// <summary>
        /// Request the contact list of the user by using iota.
        /// </summary>
        /// <returns></returns>
        private async Task<List<ContactBinding>> RequestContactListAsync()
        {
            var tmp = new List<ContactBinding>();

            var interactor = DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>();
            var response = await interactor.ExecuteAsync(new GetContactsRequest()
            {
                ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

            if (response.Code == ResponseCode.Success && (response.PendingContactRequests.Count > 0 || response.ApprovedContacts.Count > 0))
            {
                foreach (var pending in response.PendingContactRequests)
                    tmp.Add(new ContactBinding(pending, false));

                foreach (var approved in response.ApprovedContacts)
                    tmp.Add(new ContactBinding(approved, true));
            }

            return tmp;
        }

        #endregion

        #endregion



        #endregion

        #region Commands

        #region TapAddContact

        public ICommand TapAddContactCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync<AddContactView>();
                });
            }
        }

        #endregion

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
