using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Controls.InfiniteScrolling;
using Chiota.Messenger.Encryption;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetMessages;
using Chiota.Messenger.Usecase.SendMessage;
using Chiota.Models;
using Chiota.Models.Binding;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Iota;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Tangle.Net.Entity;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using Xamarin.Forms;

namespace Chiota.ViewModels.Chat
{
    public class ChatViewModel : BaseViewModel
    {
        #region Attributes

        private const int MessageSize = 32;

        private IAsymmetricKeyPair _chatKeyPair;
        private Address _chatAddress;

        private Chiota.Messenger.Entity.Contact _contact;
        private string _message;
        private InfiniteScrollCollection<MessageBinding> _messageList;
        private MessageBinding _lastMessage;
        private ImageSource _keyboardImageSource;

        private bool _isBusy;
        private bool _isKeyboardDefault;
        private bool _isLoadingMessages;

        #endregion

        #region Properties

        public Chiota.Messenger.Entity.Contact Contact
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

            var contact = (Messenger.Entity.Contact) data;

            //Set the chat address.
            _chatAddress = new Address(contact.ChatAddress);

            //Set the contact property.
            Contact = contact;

            //LoadMessages();
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
            var task = Task.Run(async () =>
            {
                var response = await DependencyResolver.Resolve<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>().ExecuteAsync(
                    new GetMessagesRequest
                    {
                        ChatAddress = _chatAddress,
                        ChatKeyPair = _chatKeyPair,
                        ChatKeyAddress = new Address(Contact.ChatKeyAddress),
                        UserKeyPair = UserService.CurrentUser.NtruKeyPair
                    });

                if (response.Code == ResponseCode.Success)
                {
                    _chatAddress = response.CurrentChatAddress;
                    _chatKeyPair = response.ChatKeyPair;

                    var messages = new List<MessageBinding>();
                    foreach (var message in response.Messages)
                    {
                        var isOwner = message.Signature != Contact.PublicKeyAddress.Substring(0, 30);
                        messages.Add(new MessageBinding(message.Message, isOwner));
                    }

                    if (MessageList == null || MessageList.Count != messages.Count)
                    {
                        MessageList?.AddRange(messages);

                        //Scroll to the current message.
                        //LastMessage = messages[messages.Count - 1];
                    }
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
                ChatKeyPair = _chatKeyPair,
                Message = tmp,
                UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
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
