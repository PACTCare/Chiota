using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Messenger.Encryption;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Messenger.Usecase.GetMessages;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Iota;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views.Chat;
using Chiota.Views.Contact;
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
            var result = new List<ChatBinding>();

            try
            {
                var response = await DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>().ExecuteAsync(new GetContactsRequest()
                {
                    ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                    PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
                });

                if (response.Code == ResponseCode.Success)
                {
                    foreach (var approved in response.ApprovedContacts)
                    {
                        var messagesResponse = await DependencyResolver.Resolve<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>().ExecuteAsync(new GetMessagesRequest
                        {
                            ChatAddress = new Address(approved.ChatAddress),
                            ChatKeyPair = null,
                            ChatKeyAddress = new Address(approved.ChatKeyAddress),
                            UserKeyPair = UserService.CurrentUser.NtruKeyPair
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
                }

                //TODO Maybe, we need to sort the chats by the last message.
            }
            catch (Exception ex)
            {

            }

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

        #region Commands


        #region Tap

        public ICommand TapCommand
        {
            get
            {
                return new Command(async (param) =>
                {
                    if (!(param is ChatBinding chat))
                    {
                        //Show an unknown exception.
                        await new UnknownException(new ExcInfo()).ShowAlertAsync();
                        return;
                    }

                    //Show the chat view.
                    await PushAsync<ChatView>(chat.Contact);
                });
            }
        }

        #endregion

        #endregion
    }
}
