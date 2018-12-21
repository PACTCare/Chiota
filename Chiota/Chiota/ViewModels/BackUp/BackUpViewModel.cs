#region References

using System.Windows.Input;
using Chiota.Resources.Localizations;
using Chiota.ViewModels.Base;
using Chiota.Services;
using Chiota.Services.DependencyInjection;
using Chiota.Services.UserServices;
using Chiota.Views.BackUp;
using Xamarin.Essentials;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.BackUp
{
    /// <summary>
    /// The back up view model.
    /// </summary>
    public class BackUpViewModel : BaseViewModel
    {
        #region Attributes

        private bool isContinueVisible;

        private UserCreationProperties UserProperties;

        #endregion

        #region Properties

        public bool IsContinueVisible
        {
            get => isContinueVisible;
            set
            {
                isContinueVisible = value;
                OnPropertyChanged(nameof(IsContinueVisible));
            }
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);

            // Set the generated iota seed.
            if (data != null)
            {
                UserProperties = data as UserCreationProperties;
            }

            // Disable the continue button.
            IsContinueVisible = false;
        }

        #endregion

        #region Reverse

        /// <inheritdoc />
        public override void Reverse(object data = null)
        {
            base.Reverse(data);

            // Enable the continue button.
            IsContinueVisible = true;
        }

        #endregion

        #region Commands

        #region WriteSeed

        public ICommand WriteSeedCommand => new Command(async () => { await PushAsync<WriteSeedView>(UserProperties.Seed.Value); });

        #endregion

        #region PrintPaper

        public ICommand PrintPaperCommand => new Command(async () => { await PushAsync<PaperCopyView>(UserProperties.Seed.Value); });

        #endregion

        #region QrCode

        public ICommand QrCodeCommand => new Command(async () => { await PushAsync<QrCodeView>(UserProperties.Seed.Value); });

        #endregion

        #region CopyToClipboard

        public ICommand CopyToClipboardCommand =>
            new Command(async () =>
            {
                await Clipboard.SetTextAsync(UserProperties.Seed.Value);
                await DisplayAlertAsync(AppResources.DlgSeedCopied, AppResources.DlgSeedCopiedDesc);
                IsContinueVisible = true;
            });

        #endregion

        #region Continue

        public ICommand ContinueCommand => new Command(async () => { await PushAsync<ConfirmSeedView>(UserProperties); });

        #endregion

        #endregion
    }
}