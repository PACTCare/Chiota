using System.Windows.Input;

using Chiota.ViewModels.Classes;

using Xamarin.Forms;

namespace Chiota.ViewModels.Help
{
    public class SeedHelpViewModel : BaseViewModel
    {
        #region Commands

        #region Continue

        public ICommand ContinueCommand => new Command(async () => { await this.PopAsync(); });

        #endregion

        #endregion
    }
}