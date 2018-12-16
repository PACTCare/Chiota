#region References

using System;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views.Settings;
using Pact.Palantir.Cache;
using Xamarin.Forms;

#endregion

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
