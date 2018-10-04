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
using Chiota.Services.DependencyInjection;
using Chiota.Services.Iota;
using Chiota.Services.MessageServices;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
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
                    var messages = MessageList.Count / MessageSize;
                    var messageService = DependencyResolver.Resolve<MessageService>();
                    var items = await messageService.GetMessagesAsync(Contact, _chatKeyPair, messages, MessageSize);

                    IsBusy = false;

                    return items;
                },
                OnCanLoadMore = () =>
                {
                    var result = false;
                    var task = Task.Run(async () =>
                    {
                        var messageService = DependencyResolver.Resolve<MessageService>();
                        var messagesCount = await messageService.GetMessagesCountAsync(Contact, _chatKeyPair);
                        result = MessageList.Count < messagesCount;
                    });
                    task.Wait();
                    
                    return result;
                }
            };
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            if (!(data is Chiota.Messenger.Entity.Contact)) return;
            var contact = (Chiota.Messenger.Entity.Contact) data;

            Contact = contact;

            //InitChatKeyPair();

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
            //Device.StartTimer(TimeSpan.FromSeconds(1), LoadMessages);
            
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

        #region InitChatKeyPair

        /// <summary>
        /// Initialize the chat key pair for encryption.
        /// </summary>
        private async void InitChatKeyPair()
        {
            /*var keyPair = NtruEncryption.Default;
            var pasSalt = await IotaHelper.GetChatPasSalt(UserService.CurrentUser, Contact.ChatKeyAddress);

            var seed = pasSalt.Substring(0, 50);
            var saltAddress = pasSalt.Substring(50, 50);
            _chatKeyPair = keyPair.CreateAsymmetricKeyPair(seed, saltAddress);*/
        }

        #endregion

        #region LoadMessages

        private bool LoadMessages()
        {
            var task = Task.Run(async () =>
            {
                var messageService = DependencyResolver.Resolve<MessageService>();
                var index = MessageList.Count / MessageSize;
                var messages = await messageService.GetMessagesAsync(Contact, _chatKeyPair, index, MessageSize);

                if (MessageList == null || MessageList.Count != messages.Count)
                {
                    //var tmp = new InfiniteScrollCollection<MessageBinding>(MessageList);
                    MessageList?.AddRange(messages);

                    //Scroll to the current message.
                    LastMessage = messages[messages.Count - 1];
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

            /*var tmp = message;
            Message = string.Empty;

            var interactor = DependencyResolver.Resolve<IUsecaseInteractor<SendMessageRequest, SendMessageResponse>>();
            var response = await interactor.ExecuteAsync(new SendMessageRequest
            {
                ChatAddress = new Address(Contact.ChatAddress),
                KeyPair = _chatKeyPair,
                Message = tmp,
                UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

            if (response.Code == ResponseCode.Success)
                return true;*/

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
