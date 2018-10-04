using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using Chiota.Messenger.Encryption;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Messenger.Usecase.GetMessages;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Iota;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Tangle.Net.Entity;
using Xamarin.Forms;

namespace Chiota.ViewModels.Chat
{
    public class ChatsViewModel : BaseViewModel
    {
        #region Attributes

        private static List<ChatBinding> _chatList;
        private bool _isUpdating;

        #endregion

        #region Properties

        public List<ChatBinding> ChatList
        {
            get => _chatList;
            set
            {
                _chatList = value;
                OnPropertyChanged(nameof(ChatList));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            UpdateView();
        }

        #endregion

        #region Methods

        #region UpdateView

        private bool UpdateView()
        {
            Device.BeginInvokeOnMainThread(async () =>
            {
                var chats = await GetChatsListAsync();
                var changed = IsChatListChanged(chats);
                if (changed)
                    ChatList = chats;
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

        #region GetChatsList

        private async Task<List<ChatBinding>> GetChatsListAsync()
        {
            var keyPair = NtruEncryption.Default;

            var result = new List<ChatBinding>();
            var response = await DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>().ExecuteAsync(new GetContactsRequest()
            {
                ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

            foreach (var approved in response.ApprovedContacts)
            {
                var pasSalt = await IotaHelper.GetChatPasSalt(UserService.CurrentUser, approved.ChatKeyAddress);
                var seed = pasSalt.Substring(0, 50);
                var saltAddress = pasSalt.Substring(50, 50);
                var chatKeyPair = keyPair.CreateAsymmetricKeyPair(seed, saltAddress);

                var messagesResponse = await DependencyResolver.Resolve<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>().ExecuteAsync(new GetMessagesRequest
                {
                    ChatAddress = new Address(approved.ChatAddress),
                    ChatKeyPair = chatKeyPair
                });

                //If the response is successful and there is an active chat, we need to add this to the list.
                if (messagesResponse.Code == ResponseCode.Success && messagesResponse.Messages.Count > 0)
                {
                    var messages = messagesResponse.Messages;
                    result.Add(new ChatBinding(approved)
                    {
                        LastMessage = messages[messages.Count - 1].Message,
                        LastMessageDateTime = messages[messages.Count - 1].Date
                    });
                }
                    
            }

            //TODO Maybe, we need to sort the chats by the last message.

            return result;
        }

        #endregion

        #region UpdateView

        /*private async void UpdateView()
        {
            //var test = await IotaHelper.GetNewMessages();

            var tmp = new List<Models.Chat>
            {
                new Models.Chat()
                {
                    Name = "David",
                    LastMessage = "Hi",
                    LastMessageTime = DateTime.Now.ToString("d", CultureInfo.CurrentCulture),
                    ImageSource = ImageSource.FromFile("account.png")
                },
                new Models.Chat()
                {
                    Name = "Sebastian",
                    LastMessage = "Great",
                    LastMessageTime = DateTime.Now.ToString("d", CultureInfo.CurrentCulture),
                    ImageSource = ImageSource.FromFile("account.png")
                }
            };

            //Add all chats of the user to the ui.
            ChatList = tmp;
        }*/

        #endregion

        #endregion
    }
}
