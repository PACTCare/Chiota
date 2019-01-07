#region References

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Controls.InfiniteScrolling;
using Chiota.Models.Binding;
using Chiota.Models.Database;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Chat
{
    public class ChatViewModel : BaseViewModel
    {
        #region Attributes

        //Max count messages for reloading for the infinitive scroll view. 
        private const int MessageSize = 16;

        private ChatBinding _chatBinding;
        private InfiniteScrollCollection<MessageBinding> _messageList;
        private bool _scrollToEnd;

        private string _message;
        private int _messageIndex;

        private bool _isLoadingMessages;

        #endregion

        #region Properties

        public ChatBinding ChatBinding
        {
            get => _chatBinding;
            set
            {
                _chatBinding = value;
                OnPropertyChanged(nameof(ChatBinding));
            }
        }

        public string Message
        {
            get => _message;
            set
            {
                _message = value;
                OnPropertyChanged(nameof(Message));
            }
        }

        public InfiniteScrollCollection<MessageBinding> MessageList
        {
            get => _messageList;
            set
            {
                _messageList = value;
                OnPropertyChanged(nameof(MessageList));
            }
        }

        public bool ScrollToEnd
        {
            get => _scrollToEnd;
            set
            {
                _scrollToEnd = value;
                OnPropertyChanged(nameof(ScrollToEnd));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            if (!(data is DbContact)) return;

            //Set the contact property.
            ChatBinding = new ChatBinding((DbContact)data);
            _messageIndex = 0;

            //Load the first package of message from the database.
            LoadMessages();

            ScrollToEnd = true;
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            //KeyboardImageSource = ImageSource.FromFile("emoticon.png");
            //_isKeyboardDefault = true;

            //Start event for loading messages.
            _isLoadingMessages = true;
            Device.StartTimer(TimeSpan.FromMilliseconds(500), LoadMessages);
            
        }

        #endregion

        #region ViewIsDisappearing

        protected override void ViewIsDisappearing()
        {
            base.ViewIsDisappearing();

            _isLoadingMessages = false;
        }

        #endregion

        #region Methods

        #region LoadMessages

        private bool LoadMessages()
        {
            var task = Task.Run(() =>
            {
                try
                {
                    var messages = Database.Message.GetMessagesByChatAddress(_chatBinding.Contact.ChatAddress, (_messageIndex + 1) * MessageSize);
                    var list = new List<MessageBinding>();

                    foreach (var item in messages)
                        list.Insert(0, new MessageBinding(item.Value, item.Date, (MessageStatus)item.Status, item.Owner));

                    if (MessageList == null || MessageList.Count != list.Count)
                    {
                        MessageList = new InfiniteScrollCollection<MessageBinding>
                        {
                            OnLoadMore = async () =>
                            {
                                //IsBusy = true;

                                //Load more messages.
                                /*var messages = MessageList.Count / MessageSize;
                                var messageService = DependencyResolver.Resolve<MessageService>();
                                var items = await messageService.GetMessagesAsync(Contact, _chatKeyPair, messages, MessageSize);*/

                                //IsBusy = false;

                                return null;
                            },
                            OnCanLoadMore = () =>
                            {
                                var result = false;
                                /*var task = Task.Run(async () =>
                                {
                                    var messageService = DependencyResolver.Resolve<MessageService>();
                                    var messagesCount = await messageService.GetMessagesCountAsync(Contact, _chatKeyPair);
                                    result = MessageList.Count < messagesCount;
                                });
                                task.Wait();*/

                                return result;
                            }
                        };

                        var newMessages = new List<MessageBinding>();
                        //Check, if it is necessary to show the date above the message in the ui.
                        for (var i = list.Count - 1; i >= MessageList.Count; i--)
                        {
                            if (newMessages.Count > 0)
                            {
                                var isLastSameDate = list[i].Date.Date == newMessages[newMessages.Count - 1].Date.Date;
                                if (!isLastSameDate)
                                    newMessages[newMessages.Count - 1].IsDateVisible = true;

                                if (i == 0)
                                    list[i].IsDateVisible = true;
                            }

                            newMessages.Add(list[i]);
                        }

                        MessageList.AddRange(newMessages);
                    }
                }
                catch (Exception)
                {
                    //Ignore
                }
            });

            task.Wait();

            return _isLoadingMessages;
        }

        #endregion

        #region SendMessage

        private void SendMessage(string value)
        {
            if (string.IsNullOrEmpty(value))
                return;

            try
            {
                //Add the new message to the database.
                var message = new DbMessage()
                {
                    ChatKeyAddress = ChatBinding.Contact.ChatKeyAddress,
                    ChatAddress = ChatBinding.Contact.CurrentChatAddress,
                    Value = value,
                    Date = DateTime.Now,
                    Status = (int) MessageStatus.Written,
                    Signature = UserService.CurrentUser.PublicKeyAddress.Substring(0, 30),
                    Owner = true,
                    ContactId = ChatBinding.Contact.Id
                };
                Database.Message.AddObject(message);
            }
            catch (Exception)
            {
                //Ignore
            }
        }

        #endregion

        #endregion

        #region Commands

        #region Info

        public ICommand InfoCommand
        {
            get
            {
                return new Command(() =>
                {

                });
            }
        }

        #endregion

        #region Action

        public ICommand ActionCommand
        {
            get
            {
                return new Command(() =>
                {
                    if (string.IsNullOrEmpty(Message))
                        return;

                    //Send new message;
                    SendMessage(Message);
                    Message = string.Empty;
                });
            }
        }

        #endregion

        #endregion
    }
}
