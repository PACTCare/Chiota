using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models;
using Chiota.Services.Share;
using Chiota.ViewModels.Classes;
using Chiota.Views.Settings;
using Xamarin.Forms;

namespace Chiota.ViewModels.Settings
{
    public class SettingsViewModel : BaseViewModel
    {
        #region Attributes

        private List<SettingsItem> _settingsList;

        #endregion

        #region Properties

        public List<SettingsItem> SettingsList
        {
            get => _settingsList;
            set
            {
                _settingsList = value;
                OnPropertyChanged(nameof(SettingsList));
            }
        }

        #endregion

        #region Constructors

        public SettingsViewModel()
        {
            //Init the settings list.
            SettingsList = new List<SettingsItem>();
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            InitView();
        }

        #endregion

        #region Methods

        #region InitView

        private void InitView()
        {
            var tmp = new List<SettingsItem>
            {
                new SettingsItem()
                {
                    Name = "Profile",
                    Icon = "account.png",
                    TapCommand = new Command(async () => { await PushAsync(new ProfileView()); })
                },
                new SettingsItem()
                {
                    Name = "Invite friends",
                    Icon = "friends.png",
                    TapCommand = new Command(async () =>
                    {
                        var title = "Chiota";
                        var message = "You should check out Chiota, your IOTA messenger!";
                        var url = "https://play.google.com/store/apps/details?id=chiotaapp.chiotaapp";

                        await CrossShare.Current.Share(new ShareMessage()
                        {
                            Title = title,
                            Text = message,
                            Url = url
                        });
                    })
                },
                new SettingsItem()
                {
                    Name = "About",
                    Icon = "help.png",
                    TapCommand = new Command(async () => { await PushAsync(new AboutView()); })
                }
            };

            SettingsList = tmp;
        }

        #endregion

        #endregion
    }
}
