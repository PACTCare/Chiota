using System.Windows.Input;

using Chiota.Pages.Authentication;
using Chiota.Pages.Help;
using Chiota.ViewModels.Classes;

using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
  using System;

  using Chiota.Annotations;

  public class WelcomeViewModel : BaseViewModel
    {
        #region Commands

        #region NewSeed

        public ICommand NewSeedCommand => new Command(async () => { await this.PushAsync(new NewSeedPage()); });

        #endregion

        #region SetSeed

        public ICommand SetSeedCommand => new Command(async () => { await this.PushAsync(new SetSeedPage()); });

        #endregion

        #region SeedHelp

        public ICommand SeedHelpCommand => new Command(async () => { await this.PushAsync(new SeedHelpPage()); });

        [UsedImplicitly]
        public ICommand PrivacyCommand => new Command(() => { Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md")); });

    #endregion

    #endregion
  }
}