#region References

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Controls.InfiniteScrolling;
using Chiota.Models.Binding;
using Chiota.Models.Database;
using Chiota.Services.BackgroundServices;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Chat
{
    public class ChatViewModel : BaseViewModel
    {
        #region Attributes

        //Max count messages for reloading for the infinitive scroll view. 
        private const int MessageSize = 32;

        private ChatBinding _chatBinding;
        private InfiniteScrollCollection<MessageBinding> _messageList;

        private string _message;
        private int _messageListHeight;

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

        public int MessageListHeight
        {
            get => _messageListHeight;
            set
            {
                _messageListHeight = value;
                OnPropertyChanged(nameof(MessageListHeight));
            }
        }

        #endregion

        #region Constructors

        public ChatViewModel()
        {
            _messageList = new InfiniteScrollCollection<MessageBinding>();

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
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            if (!(data is DbContact)) return;

            //Set the contact property.
            ChatBinding = new ChatBinding((DbContact)data);

            //Load the first package of message from the database.
            LoadMessages();
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
            Device.StartTimer(TimeSpan.FromSeconds(1), LoadMessages);
            
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
                    var messages = Database.Message.GetMessagesByChatAddress(_chatBinding.Contact.ChatAddress);
                    var list = new List<MessageBinding>();
                    var dateCounter = 0;

                    foreach (var item in messages)
                    {
                        //Check, if it is necessary to show the date above the message in the ui.
                        var isSameDate = false;

                        if (list.Count > 0)
                            isSameDate = list[list.Count - 1].Date.Date == item.Date.Date;

                        if (!isSameDate)
                            dateCounter++;

                        list.Add(new MessageBinding(item.Value, item.Date, (MessageStatus)item.Status, item.Owner, !isSameDate));
                    }

                    if (MessageList.Count != list.Count)
                    {
                        var newMessages = new List<MessageBinding>();
                        for (var i = (messages.Count - MessageList.Count) - 1; i >= MessageList.Count; i--)
                        {
                            newMessages.Add(list[i]);
                        }

                        MessageList.AddRange(newMessages);
                        //MessageListHeight = MessageList.Count * 43;
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
                    ChatAddress = ChatBinding.Contact.ChatAddress,
                    Value = value,
                    Date = DateTime.Now,
                    Status = (int) MessageStatus.Written,
                    Signature = UserService.CurrentUser.PublicKeyAddress.Substring(0, 30),
                    Owner = true
                };
                message = Database.Message.AddObject(message);

                //Start a new background job to send a message. 
                DependencyService.Get<IBackgroundJobWorker>().Run<SendMessageBackgroundJob>(UserService.CurrentUser, message);
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
                });
            }
        }

        #endregion

        #endregion
    }
}
