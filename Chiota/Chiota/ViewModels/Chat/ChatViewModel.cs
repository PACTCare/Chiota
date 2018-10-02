using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Models;
using Chiota.ViewModels.Classes;
using Xamarin.Forms;

namespace Chiota.ViewModels.Chat
{
    public class ChatViewModel : BaseViewModel
    {
        #region Attributes

        private string _contactName;
        private string _message;
        private List<MessageBinding> _messageList;
        private ImageSource _keyboardImageSource;
        private Keyboard _keyboardType;
        private bool _isEntryFocused;
        private bool _isKeyboardDefault;

        #endregion

        #region Properties

        public string ContactName
        {
            get => _contactName;
            set
            {
                _contactName = value;
                OnPropertyChanged(nameof(ContactName));
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

            ContactName = contact.Name;
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

        private void SendMessage(string message)
        {
            var tmp = new List<MessageBinding>(MessageList);
            tmp.Add(new MessageBinding(message, false, true));

            MessageList = tmp;

            //Clear user input.
            Message = "";
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
                    SendMessage(Message);
                });
            }
        }

        #endregion

        #endregion
    }
}
