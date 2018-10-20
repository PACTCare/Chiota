using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Messenger.Cache;
using Chiota.Messenger.Encryption;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetContacts;
using Chiota.Messenger.Usecase.GetMessages;
using Chiota.Models;
using Chiota.Models.Binding;
using Chiota.Services.Database;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Iota;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views.Chat;
using Chiota.Views.Contact;
using Chiota.Views.Settings;
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

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            _isUpdating = true;
            Device.StartTimer(TimeSpan.FromSeconds(1), UpdateView);
        }

        #endregion

        #region ViewIsDisappearing

        protected override void ViewIsDisappearing()
        {
            base.ViewIsDisappearing();

            _isUpdating = false;
        }

        #endregion

        #region Methods

        #region UpdateView

        /// <summary>
        /// Init the view with the user data of the database.
        /// </summary>
        private bool UpdateView()
        {
            var chats = new List<ChatBinding>();

            //Load all accepted contacts.
            var contacts = DatabaseService.Contact.GetAcceptedContacts();
            foreach (var item in contacts)
            {
                var lastMessage = DatabaseService.Message.GetObjectById(0);

                //If there is a message, load the chat of the contact.
                if (lastMessage != null)
                {
                    var contact = new Messenger.Entity.Contact()
                    {
                        Name = item.Name,
                        ImageHash = item.ImageHash,
                        ChatAddress = item.ChatAddress,
                        ChatKeyAddress = item.ChatKeyAddress,
                        PublicKeyAddress = item.PublicKeyAddress,
                        Rejected = !item.Accepted
                    };
                    chats.Add(new ChatBinding(contact));
                }
            }

            //Update the chat list.
            var changed = IsChatListChanged(chats);
            if (changed)
                ChatList = chats;

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

        #endregion

        #region Commands

        #region Contacts

        public ICommand ContactsCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync<ContactsView>();
                });
            }
        }

        #endregion

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
