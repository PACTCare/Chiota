#region References

using Chiota.Resources.Localizations;
using Chiota.ViewModels.Base;

#endregion

namespace Chiota.ViewModels.Settings
{
    public class AboutViewModel : BaseViewModel
    {
        #region Attributes

        private string _version;

        #endregion

        #region Properties

        public string Version
        {
            get => _version;
            set
            {
                _version = value;
                OnPropertyChanged(nameof(Version));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            //Set the version of the installed app.
            Version = AppResources.DlgVersion + " " + Xamarin.Essentials.AppInfo.VersionString;
        }

        #endregion
    }
}
