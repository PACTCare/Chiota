#region References

using System.Windows.Input;
using Chiota.ViewModels.Base;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Help
{
    public class SeedHelpViewModel : BaseViewModel
    {
        #region Commands

        #region Continue

        public ICommand ContinueCommand => new Command(async () => { await PopAsync(); });

        #endregion

        #endregion
    }
}