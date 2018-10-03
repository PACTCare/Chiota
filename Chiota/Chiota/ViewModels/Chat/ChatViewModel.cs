using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Messenger.Usecase;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Chiota.ViewModels.Classes;
using Xamarin.Forms;

namespace Chiota.ViewModels.Chat
{
    public class ChatViewModel : BaseViewModel
    {
        #region Attributes

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

            return true;
            /*var interactor = DependencyResolver.Resolve<IUsecaseInteractor<SendMessageRequest, SendMessageResponse>>();
            var response = await interactor.ExecuteAsync(new SendMessageRequest
            {
                ChatAddress = Contact.ChatAddress,
                KeyPair = NtruEncryption.Default,
            });*/

            /*if (this.OutGoingText?.Length > 0)
      {
        await this.DisplayLoadingSpinnerAsync("Sending Message");

        this.loadNewMessages = false;

        var interactor = DependencyResolver.Resolve<IUsecaseInteractor<SendMessageRequest, SendMessageResponse>>();
        var response = await interactor.ExecuteAsync(
          new SendMessageRequest
            {
              ChatAddress = this.currentChatAddress,
              KeyPair = this.ntruChatKeyPair,
              Message = this.OutGoingText,
              UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

        this.loadNewMessages = true;
        await this.AddNewMessagesAsync(this.Messages);
        this.OutGoingText = null;

        await this.PopPopupAsync();

        await SendMessagePresenter.Present(this, response);
}*/



            /*var tmp = new List<MessageBinding>(MessageList);
            tmp.Add(new MessageBinding(message));

            MessageList = tmp;

            //Clear user input.
            Message = "";*/
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
