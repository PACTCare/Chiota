namespace Chiota.ViewModels.BackUp
{
    using System.Windows.Input;

    using Chiota.Annotations;
    using Chiota.Services;
    using Chiota.Services.DependencyInjection;
    using Chiota.Services.UserServices;
    using Chiota.ViewModels.Classes;
    using Chiota.Views.BackUp;

    using Xamarin.Forms;

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
            get => this.isContinueVisible;
            set
            {
                this.isContinueVisible = value;
                this.OnPropertyChanged(nameof(this.IsContinueVisible));
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
                this.UserProperties = data as UserCreationProperties;
            }

            // Disable the continue button.
            this.IsContinueVisible = true;
        }

        #endregion

        #region Reverse

        /// <inheritdoc />
        public override void Reverse(object data = null)
        {
            base.Reverse(data);

            // Enable the continue button.
            this.IsContinueVisible = true;
        }

        #endregion

        #region Commands

        #region WriteSeed

        public ICommand WriteSeedCommand => new Command(async () => { await this.PushAsync(new WriteSeedView(), this.UserProperties.Seed.Value); });

        #endregion

        #region PrintPaper

        public ICommand PrintPaperCommand => new Command(async () => { await this.PushAsync(new PaperCopyView(), this.UserProperties.Seed.Value); });

        #endregion

        #region QrCode

        public ICommand QrCodeCommand => new Command(async () => { await this.PushAsync(new QrCodeView(), this.UserProperties.Seed.Value); });

        #endregion

        #region CopyToClipboard

        public ICommand CopyToClipboardCommand =>
            new Command(async () =>
            {
                DependencyResolver.Resolve<IClipboardService>().SendTextToClipboard(this.UserProperties.Seed.Value);
                await this.PushAlertAsync("Seed copied", "The seed has been copied to your clipboard");
            });

        #endregion

        #region Continue

        public ICommand ContinueCommand => new Command(async () => { await this.PushAsync(new ConfirmSeedView(), this.UserProperties); });

        #endregion

        #endregion
    }
}