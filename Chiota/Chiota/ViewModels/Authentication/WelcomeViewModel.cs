#region References

using System;
using Chiota.Annotations;
using Chiota.Views.Authentication;
using Chiota.Views.Help;
using System.Windows.Input;
using Chiota.ViewModels.Base;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Authentication
{
    public class WelcomeViewModel : BaseViewModel
    {
        #region Commands

        #region NewSeed

        public ICommand NewSeedCommand => new Command(async () => { await PushAsync<NewSeedView>(); });

        #endregion

        #region SetSeed

        public ICommand SetSeedCommand => new Command(async () => { await PushAsync<SetSeedView>(); });

        #endregion

        #region SeedHelp

        public ICommand SeedHelpCommand => new Command(async () => { await PushAsync<SeedHelpView>(); });

        [UsedImplicitly]
        public ICommand PrivacyCommand => new Command(() => { Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md")); });

        #endregion

        #endregion
    }
}