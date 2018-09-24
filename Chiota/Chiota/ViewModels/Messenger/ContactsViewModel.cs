using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Tangle.Net.Entity;
using Xamarin.Forms;

namespace Chiota.ViewModels.Messenger
{
    public class ContactsViewModel : BaseViewModel
    {
        #region Attributes

        private List<ContactBinding> _contactList;

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

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            UpdateViewAsync();

            base.ViewIsAppearing();
        }

        #endregion

        #region Methods

        #region UpdateView

        private async void UpdateViewAsync()
        {
            await PushLoadingSpinnerAsync("Loading");
            ContactList = await GetContactListAsync();
            await PopPopupAsync();
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

            foreach (var approved in response.ApprovedContacts)
                tmp.Add(new ContactBinding(approved, true));

            foreach (var pending in response.PendingContactRequests)
                tmp.Add(new ContactBinding(pending, false));

            return tmp;
        }

        #endregion

        #endregion
    }
}
