using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Messenger.Cache;
using Chiota.Models.Binding;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views.Chat;
using Chiota.Views.Contact;
using Chiota.Views.Settings;
using Xamarin.Forms;

namespace Chiota.ViewModels.Tabbed
{
    public class TabbedNavigationViewModel : BaseViewModel
    {
        #region Commands

        #region Search

        public ICommand SearchCommand
        {
            get
            {
                return new Command(() =>
                {
                });
            }
        }

        #endregion

        #region ContactAddress

        public ICommand ContactAddressCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PushAsync<ContactAddressView>();
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
                    await PushAsync<SettingsView>();
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
                    try
                    {
                        var userService = DependencyResolver.Resolve<UserService>();
                        userService.SetCurrentUser(null);
                        await DependencyResolver.Resolve<ITransactionCache>().FlushAsync();
                    }
                    catch (Exception)
                    {

                    }

                    AppBase.ShowStartUp();
                });
            }
        }

        #endregion

        #endregion
    }
}
