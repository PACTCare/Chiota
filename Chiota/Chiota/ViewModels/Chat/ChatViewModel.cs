#region References

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Controls.InfiniteScrolling;
using Chiota.Models.Binding;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.SendMessage;
using Tangle.Net.Entity;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Chat
{
    public class ChatViewModel : BaseViewModel
    {
        #region Attributes

        private const int MessageSize = 64;

        private IAsymmetricKeyPair _chatKeyPair;
        private Pact.Palantir.Entity.Contact _contact;
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

        public Pact.Palantir.Entity.Contact Contact
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

            if (!(data is Pact.Palantir.Entity.Contact)) return;

            //Set the contact property.
            Contact = (Pact.Palantir.Entity.Contact)data;

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
                var messages = Database.Message.GetMessagesByPublicKeyAddress(_contact.PublicKeyAddress);
                var list = new List<MessageBinding>();

                foreach (var item in messages)
                {
                    var message = new MessageBinding(item.Value, item.Owner, item.Date);
                    list.Add(message);
                }

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
            });

            task.Wait();

            return _isLoadingMessages;
        }

        #endregion

        #region SendMessage

        private async Task<bool> SendMessageAsync(string message)
        {
            if (string.IsNullOrEmpty(message))
                return false;

            var tmp = message;
            Message = string.Empty;

            var response = await DependencyResolver.Resolve<IUsecaseInteractor<SendMessageRequest, SendMessageResponse>>().ExecuteAsync(new SendMessageRequest
            {
                ChatAddress = new Address(Contact.ChatAddress),
                ChatKeyAddress = new Address(Contact.ChatKeyAddress),
                UserKeyPair = UserService.CurrentUser.NtruKeyPair,
                UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                Message = tmp
            });

            if (response.Code == ResponseCode.Success)
                return true;

            return false;
        }

        #endregion

        #endregion

        #region Commands

        #region Action

        public ICommand ActionCommand
        {
            get
            {
                return new Command(async () =>
                {
                    if (string.IsNullOrEmpty(Message))
                        return;

                    //Send new message;
                    await SendMessageAsync(Message);
                });
            }
        }

        #endregion

        #endregion
    }
}
