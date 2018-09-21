using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Classes;
using Chiota.Messenger.Cache;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views.Authentication;
using Chiota.Views.Contact;
using Chiota.Views.Profile;
using Chiota.Views.Settings;
using Xamarin.Forms;

namespace Chiota.ViewModels.Messenger
{
    public class MessengerTabbedViewModel : BaseViewModel
    {
        #region Commands

        #region ContactAddress

        public ICommand ContactAddressCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new ContactAddressView());
                });
            }
        }

        #endregion

        #region AddContact

        public ICommand AddContactCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new AddContactView());
                });
            }
        }

        #endregion

        #region Settings

        public ICommand SettingsCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync(new SettingsView());
                });
            }
        }

        #endregion

        #region LogOut

        public ICommand LogOutCommand
        {
            get
            {
                return new Command(async () =>
                {
                    UserService.SetCurrentUser(null);
                    await DependencyResolver.Resolve<ITransactionCache>().FlushAsync();
                    AppNavigation.ShowStartUp();
                });
            }
        }

        #endregion

        #endregion
    }
}
