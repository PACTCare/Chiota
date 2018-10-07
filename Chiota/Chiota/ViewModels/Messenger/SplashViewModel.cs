using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Base;
using Chiota.ViewModels.Base;
using Xamarin.Forms;

namespace Chiota.ViewModels.Messenger
{
    public class SplashViewModel : BaseViewModel
    {
        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            Device.BeginInvokeOnMainThread(async () =>
            {
                AppBase.NavigationInstance.InitObject = true;
                await AppBase.ShowStartUpAsync();
            });
        }

        #endregion
    }
}
