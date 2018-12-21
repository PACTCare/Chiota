#region References

using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Models.Binding;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupViewModels;
using Chiota.Popups.PopupViews;
using Chiota.Resources.Localizations;
using Chiota.ViewModels.Base;
using Chiota.Views.Chat;
using Chiota.Views.Contact;
using Rg.Plugins.Popup.Pages;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Chat
{
    public class ChatActionsViewModel : BaseViewModel
    {
        #region Attributes

        private const int ActionItemHeight = 49;
        private const int ContactItemHeight = 69;

        private List<ActionBinding> _actionList;
        private List<ContactBinding> _contactList;

        private int _actionListHeight;
        private int _contactListHeight;

        private bool _isContactExist;

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

        public int ContactListHeight
        {
            get => _contactListHeight;
            set
            {
                _contactListHeight = value;
                OnPropertyChanged(nameof(ContactListHeight));
            }
        }

        public bool IsContactExist
        {
            get => _isContactExist;
            set
            {
                _isContactExist = value;
                OnPropertyChanged(nameof(IsContactExist));
            }
        }

        #endregion

        #region Constructors

        public ChatActionsViewModel()
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
            ActionListHeight = ActionList.Count * ActionItemHeight;

            //Load all contacts.
            ContactList = LoadContactListByDb();
            ContactListHeight = ContactList.Count * ContactItemHeight;
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
                var contacts = Database.Contact.GetAcceptedContacts();
                foreach (var item in contacts)
                {
                    if(item.Name == null || item.ContactAddress == null || item.ChatKeyAddress == null) continue;

                    var exist = list.Any(t => t.Contact.ChatAddress == item.ChatAddress);
                    if (!exist)
                    {
                        var contact = new Pact.Palantir.Entity.Contact()
                        {
                            ChatAddress = item.ChatAddress,
                            Name = item.Name,
                            ImagePath = item.ImagePath,
                            ChatKeyAddress = item.ChatKeyAddress,
                            ContactAddress = item.ContactAddress,
                            PublicKeyAddress = item.PublicKeyAddress,
                            Rejected = !item.Accepted
                        };
                        list.Add(new ContactBinding(contact, item.Accepted, item.ImageBase64));
                    }
                }

                IsContactExist = list.Count > 0;
            }
            catch (Exception)
            {
                //By error return the last list.
                list = ContactList;
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
                        {
                            await PushAsync<ChatView>(contact.Contact);
                            return;
                        }
                    }
                    else if (param is ActionBinding action)
                    {
                        if (action.Name == AppResources.CmnNewContact)
                        {
                            await DisplayPopupAsync<AddContactPopupViewModel, AddContactPopupModel>(new AddContactPopupView());
                            return;
                        }
                    }

                    //Show an unknown exception.
                    await new UnknownException(new ExcInfo()).ShowAlertAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
