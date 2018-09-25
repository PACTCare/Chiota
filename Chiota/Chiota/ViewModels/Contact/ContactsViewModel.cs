using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Tangle.Net.Entity;
using Xamarin.Forms;

namespace Chiota.ViewModels.Contact
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

        #region Init

        protected override void ViewIsAppearing()
        {
            UpdateView();

            base.ViewIsAppearing();
        }

        #endregion

        #region Methods

        #region UpdateView

        private async void UpdateView()
        {
            ContactList = await GetContactListAsync();
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

        #region Commands

        #region Refresh

        public ICommand RefreshCommand
        {
            get
            {
                return new Command(() =>
                {
                    UpdateView();
                });
            }
        }

        #endregion

        #endregion
    }
}
