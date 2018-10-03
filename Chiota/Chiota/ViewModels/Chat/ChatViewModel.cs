using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Messenger.Encryption;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.SendMessage;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Iota;
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

        private IAsymmetricKeyPair _chatKeyPair;
        private Chiota.Messenger.Entity.Contact _contact;
        private string _message;
        private List<MessageBinding> _messageList;
        private ImageSource _keyboardImageSource;
        private Keyboard _keyboardType;
        private bool _isEntryFocused;
        private bool _isKeyboardDefault;

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

        public List<MessageBinding> MessageList
        {
            get => _messageList;
            set
            {
                _messageList = value;
                OnPropertyChanged(nameof(MessageList));
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

        public Keyboard KeyboardType
        {
            get => _keyboardType;
            set
            {
                _keyboardType = value;
                OnPropertyChanged(nameof(KeyboardType));
            }
        }

        public bool IsEntryFocused
        {
            get => _isEntryFocused;
            set
            {
                _isEntryFocused = value;
                OnPropertyChanged(nameof(IsEntryFocused));
            }
        }

        #endregion

        #region Constructors

        public ChatViewModel()
        {
            MessageList = new List<MessageBinding>();
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            if (!(data is Chiota.Messenger.Entity.Contact)) return;
            var contact = (Chiota.Messenger.Entity.Contact) data;

            Contact = contact;

            InitChatKeyPair();
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            KeyboardImageSource = ImageSource.FromFile("emoticon.png");
            KeyboardType = Keyboard.Default;
            _isKeyboardDefault = true;
        }

        #endregion

        #region Methods

        #region InitChatKeyPair

        /// <summary>
        /// Initialize the chat key pair for encryption.
        /// </summary>
        private async void InitChatKeyPair()
        {
            var keyPair = NtruEncryption.Default;
            var pasSalt = await IotaHelper.GetChatPasSalt(UserService.CurrentUser, Contact.ChatKeyAddress);

            var seed = pasSalt.Substring(0, 50);
            var saltAddress = pasSalt.Substring(50, 50);
            _chatKeyPair = keyPair.CreateAsymmetricKeyPair(seed, saltAddress);
        }

        #endregion

        #region GetMessages

        private void GetMessages()
        {
        }

        #endregion

        #region SendMessage

        private async Task<bool> SendMessageAsync(string message)
        {
            if (string.IsNullOrEmpty(message))
                return false;

            var tmp = message;
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
                return true;

            return false;
        }

        #endregion

        #endregion

        #region Commands

        #region Keyboard

        public ICommand KeyboardCommand
        {
            get
            {
                return new Command(() =>
                {
                    if (_isKeyboardDefault)
                    {
                        KeyboardImageSource = ImageSource.FromFile("keyboard.png");
                        KeyboardType = Keyboard.Chat;

                        IsEntryFocused = true;
                    }
                    else
                    {
                        KeyboardImageSource = ImageSource.FromFile("emoticon.png");
                        KeyboardType = Keyboard.Default;

                        IsEntryFocused = true;
                    }

                    _isKeyboardDefault = !_isKeyboardDefault;
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
                    SendMessageAsync(Message);
                });
            }
        }

        #endregion

        #endregion
    }
}
