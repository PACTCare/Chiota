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

        private IAsymmetricKeyPair _chatKeyPair;
        private DbContact _contact;
        private string _message;
        private InfiniteScrollCollection<MessageBinding> _messageList;
        private MessageBinding _lastMessage;
        private ImageSource _keyboardImageSource;

        private int _messageListHeight;

        private bool _isBusy;
        private bool _isKeyboardDefault;
        private bool _isLoadingMessages;

        #endregion

        #region Properties

        public DbContact Contact
        {
            get => _contact;
            set
            {
                _contact = value;
                OnPropertyChanged(nameof(Contact));
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

        public MessageBinding LastMessage
        {
            get => _lastMessage;
            set
            {
                _lastMessage = value;
                OnPropertyChanged(nameof(LastMessage));
            }
        }

        public ImageSource KeyboardImageSource
        {
            get => _keyboardImageSource;
            set
            {
                _keyboardImageSource = value;
                OnPropertyChanged(nameof(KeyboardImageSource));
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

        public bool IsBusy
        {
            get => _isBusy;
            set
            {
                _isBusy = value;
                OnPropertyChanged(nameof(IsBusy));
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
                    IsBusy = true;

                    //Load more messages.
                    /*var messages = MessageList.Count / MessageSize;
                    var messageService = DependencyResolver.Resolve<MessageService>();
                    var items = await messageService.GetMessagesAsync(Contact, _chatKeyPair, messages, MessageSize);*/

                    IsBusy = false;

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
            Contact = (DbContact)data;

            //Load the first package of message from the database.
            LoadMessages();
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            KeyboardImageSource = ImageSource.FromFile("emoticon.png");
            _isKeyboardDefault = true;

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
                    var messages = Database.Message.GetMessagesByChatAddress(_contact.ChatAddress);
                    var list = new List<MessageBinding>();

                    foreach (var item in messages)
                        list.Add(new MessageBinding(item.Value, item.Date, (MessageStatus)item.Status, item.Owner));

                    if (MessageList.Count != list.Count)
                    {
                        var newMessages = new List<MessageBinding>();
                        for (var i = (messages.Count - MessageList.Count) - 1; i >= MessageList.Count; i--)
                        {
                            newMessages.Add(list[i]);
                        }

                        MessageList.AddRange(newMessages);
                        MessageListHeight = MessageList.Count * 43;
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
                    ChatKeyAddress = Contact.ChatKeyAddress,
                    ChatAddress = Contact.ChatAddress,
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
