using System;
using System.Collections.Generic;
using System.Globalization;
using Chiota.ViewModels.Classes;
using Xamarin.Forms;

namespace Chiota.ViewModels.Chat
{
    public class ChatsViewModel : BaseViewModel
    {
        #region Attributes

        private static List<Models.Chat> _chatList;

        #endregion

        #region Properties

        public List<Models.Chat> ChatList
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
            UpdateView();

            base.Init(data);
        }

        #endregion

        #region Methods

        #region UpdateView

        private async void UpdateView()
        {
            //var test = await IotaHelper.GetNewMessages();

            var tmp = new List<Models.Chat>
            {
                new Models.Chat()
                {
                    Name = "David",
                    LastMessage = "Hi",
                    LastMessageTime = DateTime.Now.ToString("d", CultureInfo.CurrentCulture),
                    ImageSource = ImageSource.FromFile("account.png")
                },
                new Models.Chat()
                {
                    Name = "Sebastian",
                    LastMessage = "Great",
                    LastMessageTime = DateTime.Now.ToString("d", CultureInfo.CurrentCulture),
                    ImageSource = ImageSource.FromFile("account.png")
                }
            };

            //Add all chats of the user to the ui.
            ChatList = tmp;
        }

        #endregion

        #endregion
    }
}
