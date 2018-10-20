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
using Chiota.Resources.Localizations;
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

        private List<ActionBinding> _actionList;
        private List<ContactBinding> _contactList;

        private int _actionListHeight;

        #endregion

        #region Properties

        public List<ActionBinding> ActionList
        {
            get => _actionList;
            set
            {
                _actionList = value;
                OnPropertyChanged(nameof(ActionList));
            }
        }

        public List<ContactBinding> ContactList
        {
            get => _contactList;
            set
            {
                _contactList = value;
                OnPropertyChanged(nameof(ContactList));
            }
        }

        public int ActionListHeight
        {
            get => _actionListHeight;
            set
            {
                _actionListHeight = value;
                OnPropertyChanged(nameof(ActionListHeight));
            }
        }

        #endregion

        #region Constructors

        public ContactsViewModel()
        {
            _actionList = new List<ActionBinding>();
            _contactList = new List<ContactBinding>();
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            InitView();
        }

        #endregion

        #region Methods

        #region InitView

        /// <summary>
        /// Init the view with all actions and the contact list.
        /// </summary>
        private void InitView()
        {
            //Create the action list.
            var actionList = new List<ActionBinding>
            {
                new ActionBinding() { Name = AppResources.CmnNewContact, ImageSource = ImageSource.FromFile("addperson.png") },
            };

            ActionList = actionList;
            ActionListHeight = ActionList.Count * 48;

            //Load all contacts.
            ContactList = LoadContactListByDb();
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
                //By error return an empty list.
                list = new List<ContactBinding>();
            }

            return list;
        }

        #endregion

        #endregion

        #region Commands

        #region ContactAddress

        public ICommand ContactAddressCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync<ContactAddressView>();
                });
            }
        }

        #endregion

        #region Tap

        /// <summary>
        /// Tap command on a contact or action item.
        /// </summary>
        public ICommand TapCommand
        {
            get
            {
                return new Command(async (param) =>
                {
                    if (param is ContactBinding contact)
                    {
                        //Show the chat view, or a dialog for a contact request acceptation.
                        if (contact.IsApproved)
                            await PushAsync<ChatView>(contact.Contact);
                        else
                            await PushAsync<ContactRequestView>(contact.Contact);
                    }
                    else if (param is ActionBinding action)
                    {
                        if(action.Name == AppResources.CmnNewContact)
                            await PushAsync<AddContactView>();
                    }
                    else
                    {
                        //Show an unknown exception.
                        await new UnknownException(new ExcInfo()).ShowAlertAsync();
                    }
                });
            }
        }

        #endregion

        #endregion
    }
}
