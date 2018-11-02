using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Models.Binding;
using Chiota.Services.Database;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views.Chat;
using Chiota.Views.Contact;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.GetContacts;
using Pact.Palantir.Usecase.GetMessages;
using Tangle.Net.Entity;
using Xamarin.Essentials;
using Xamarin.Forms;

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

            //UpdateView();
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();
        
            _isUpdating = true;
            //Device.StartTimer(TimeSpan.FromMinutes(1), UpdateView);
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
            var task = Task.Run(async () =>
            {
                var chats = new List<ChatBinding>();

                try
                {
                    //Load all accepted contacts.
                    var contacts = DatabaseService.Contact.GetAcceptedContacts();
                    foreach (var item in contacts)
                    {
                        /*var response = await DependencyResolver.Resolve<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>().ExecuteAsync(
                            new GetMessagesRequest
                            {
                                ChatAddress = new Address(item.ChatAddress),
                                ChatKeyAddress = new Address(item.ChatKeyAddress),
                                UserKeyPair = UserService.CurrentUser.NtruKeyPair
                            });

                        //If there is a message, load the chat of the contact.
                        if (response.Code == ResponseCode.Success && response.Messages.Count > 0)
                        {
                            var lastMessage = response.Messages[response.Messages.Count - 1];
                            var contact = new Pact.Palantir.Entity.Contact()
                            {
                                Name = item.Name,
                                ImagePath = item.ImagePath,
                                ChatAddress = item.ChatAddress,
                                ChatKeyAddress = item.ChatKeyAddress,
                                PublicKeyAddress = item.PublicKeyAddress,
                                Rejected = !item.Accepted
                            };
                            chats.Add(new ChatBinding(contact, lastMessage.Message, lastMessage.Date));
                        }*/


                        /*var lastMessage = DatabaseService.Message.GetObjectById(0);

                        //If there is a message, load the chat of the contact.
                        if (lastMessage != null)
                        {
                            var contact = new Pact.Palantir.Entity.Contact()
                            {
                                Name = item.Name,
                                ImagePath = item.ImagePath,
                                ChatAddress = item.ChatAddress,
                                ChatKeyAddress = item.ChatKeyAddress,
                                PublicKeyAddress = item.PublicKeyAddress,
                                Rejected = !item.Accepted
                            };
                            chats.Add(new ChatBinding(contact));
                        }*/
                    }
                }
                catch (Exception)
                {

                }

                

                //Update the chat list.
                var changed = IsChatListChanged(chats);
                if (changed)
                {
                    ChatList = chats;
                    ChatListHeight = chats.Count * ChatItemHeight;
                }
            });
            task.Wait();

            //If there is an internet connection, try to get the contact requests of the user.
            if (Connectivity.NetworkAccess == NetworkAccess.Internet)
            {
                Device.BeginInvokeOnMainThread(async () =>
                {
                    /*var response = await DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>().ExecuteAsync(
                        new GetContactsRequest
                        {
                            RequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                            PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                            KeyPair = UserService.CurrentUser.NtruKeyPair
                        });

                    if (response.Code == ResponseCode.Success && response.PendingContactRequests.Count > 0)
                    {
                        var requests = new List<ContactBinding>();

                        foreach (var item in response.PendingContactRequests)
                            requests.Add(new ContactBinding(item, false));

                        //Update the request list.
                        if (RequestList.Count != requests.Count)
                        {
                            RequestList = requests;
                            RequestListHeight = requests.Count * RequestItemHeight;
                            IsRequestExist = requests.Count > 0;
                        }
                        return;
                    }*/

                    //Reset the request list.
                    RequestList = null;
                    IsRequestExist = false;
                    RequestListHeight = 0;
                });
            }

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
                    await PushAsync<ContactsView>();
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
