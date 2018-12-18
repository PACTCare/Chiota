#region References

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Models.Binding;
using Chiota.ViewModels.Base;
using Chiota.Views.Chat;
using Chiota.Views.Contact;
using Xamarin.Forms;
using ChatActionsView = Chiota.Views.Chat.ChatActionsView;

#endregion

namespace Chiota.ViewModels.Chat
{
    public class ChatsViewModel : BaseViewModel
    {
        #region Attributes

        private const int RequestItemHeight = 64;
        private const int ChatItemHeight = 72;

        private static List<ContactBinding> _requestList;
        private static List<ChatBinding> _chatList;

        private int _requestListHeight;
        private int _chatListHeight;

        private bool _isRequestExist;
        private bool _isChatExist;
        private bool _isAnyExist;
        private bool _isNoneExist;

        private bool _isUpdating;

        #endregion

        #region Properties

        public List<ContactBinding> RequestList
        {
            get => _requestList;
            set
            {
                _requestList = value;
                OnPropertyChanged(nameof(RequestList));
            }
        }

        public List<ChatBinding> ChatList
        {
            get => _chatList;
            set
            {
                _chatList = value;
                OnPropertyChanged(nameof(ChatList));
            }
        }

        public int RequestListHeight
        {
            get => _requestListHeight;
            set
            {
                _requestListHeight = value;
                OnPropertyChanged(nameof(RequestListHeight));
            }
        }

        public int ChatListHeight
        {
            get => _chatListHeight;
            set
            {
                _chatListHeight = value;
                OnPropertyChanged(nameof(ChatListHeight));
            }
        }

        public bool IsRequestExist
        {
            get => _isRequestExist;
            set
            {
                _isRequestExist = value;
                OnPropertyChanged(nameof(IsRequestExist));
            }
        }

        public bool IsChatExist
        {
            get => _isChatExist;
            set
            {
                _isChatExist = value;
                OnPropertyChanged(nameof(IsChatExist));
            }
        }

        public bool IsAnyExist
        {
            get => _isAnyExist;
            set
            {
                _isAnyExist = value;
                OnPropertyChanged(nameof(IsAnyExist));
            }
        }

        public bool IsNoneExist
        {
            get => _isNoneExist;
            set
            {
                _isNoneExist = value;
                OnPropertyChanged(nameof(IsNoneExist));
            }
        }

        #endregion

        #region Constructors

        public ChatsViewModel()
        {
            _requestList = new List<ContactBinding>();
            _chatList = new List<ChatBinding>();
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            UpdateView();
        }

        #endregion

        #region Reverse

        public override void Reverse(object data = null)
        {
            base.Reverse(data);

            UpdateView();
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();
        
            _isUpdating = true;
            Device.StartTimer(TimeSpan.FromSeconds(10), UpdateView);
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
        /// Init the view with the user data of the database and the contact requests by valid connection.
        /// </summary>
        private bool UpdateView()
        {
            //Show the contact requests of the user.
            Task.Run(() =>
            {
                var contactRequests = new List<ContactBinding>();

                var requests = Database.Contact.GetUnacceptedContacts();
                if (requests.Count <= 0)
                {
                    //Reset the request list.
                    RequestList = null;
                    IsRequestExist = false;
                    RequestListHeight = 0;
                    return;
                }

                foreach (var item in requests)
                {
                    var contact = new Pact.Palantir.Entity.Contact()
                    {
                        Name = item.Name,
                        ImagePath = item.ImagePath,
                        ChatAddress = item.ChatAddress,
                        ChatKeyAddress = item.ChatKeyAddress,
                        ContactAddress = item.ContactAddress,
                        PublicKeyAddress = item.PublicKeyAddress,
                        Rejected = !item.Accepted
                    };
                    contactRequests.Add(new ContactBinding(contact, false, item.ImageBase64));
                }

                //Set flag to show the contact requests.
                IsRequestExist = contactRequests.Count > 0;
                IsAnyExist = contactRequests.Count > 0;
                IsNoneExist = !(contactRequests.Count > 0);

                //Update the request list.
                if ( RequestList == null || RequestList.Count != contactRequests.Count)
                {
                    RequestList = contactRequests;
                    RequestListHeight = contactRequests.Count * RequestItemHeight;
                }
            });

            //Show the chats of the user.
            Task.Run(() =>
            {
                var chats = new List<ChatBinding>();

                //Load all accepted contacts.
                var contacts = Database.Contact.GetAcceptedContacts();
                foreach (var item in contacts)
                {
                    //Get the last message of the contact.
                    var lastMessage = Database.Message.GetLastMessagesByPublicKeyAddress(item.PublicKeyAddress);

                    if (lastMessage == null) continue;

                    //If there is a message, load the chat of the contact.
                    var contact = new Pact.Palantir.Entity.Contact()
                    {
                        Name = item.Name,
                        ImagePath = item.ImagePath,
                        ChatAddress = item.ChatAddress,
                        ChatKeyAddress = item.ChatKeyAddress,
                        ContactAddress = item.ContactAddress,
                        PublicKeyAddress = item.PublicKeyAddress,
                        Rejected = !item.Accepted
                    };
                    chats.Add(new ChatBinding(contact, lastMessage.Value, lastMessage.Date));
                }


                //Set flag to show the chats.
                IsChatExist = chats.Count > 0;
                IsAnyExist = chats.Count > 0;
                IsNoneExist = !(chats.Count > 0);

                //Update the chat list.
                var changed = IsChatListChanged(chats);
                if (changed)
                {
                    ChatList = chats;
                    ChatListHeight = chats.Count * ChatItemHeight;
                }
            });

            return _isUpdating;
        }

        #endregion

        #region IsChatsListChanged

        private bool IsChatListChanged(List<ChatBinding> chats)
        {
            if (ChatList == null || ChatList.Count != chats.Count)
                return true;

            return false;
        }

        #endregion

        #endregion

        #region Commands

        #region Contacts

        public ICommand ContactsCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync<ChatActionsView>();
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
                    if (param is ChatBinding chat)
                    {
                        //Show the chat view.
                        await PushAsync<ChatView>(chat.Contact);
                        return;
                    }
                    else if (param is ContactBinding contact)
                    {
                        //Show the chat view, or a dialog for a contact request acceptation.
                        if (!contact.IsApproved)
                        {
                            await PushAsync<ContactRequestView>(contact.Contact);
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
