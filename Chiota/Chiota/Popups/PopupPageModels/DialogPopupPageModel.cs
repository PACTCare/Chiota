namespace Chiota.Popups.PopupPageModels
{
    using System.Windows.Input;

    using Chiota.Popups.Classes;
    using Chiota.Popups.PopupModels;

    using Xamarin.Forms;

    public class DialogPopupPageModel : BasePopupPageModel<DialogPopupModel>
    {
        public DialogPopupPageModel()
          : base()
        {
        }

        public DialogPopupPageModel(DialogPopupModel popupModel)
          : base(popupModel)
        {
            if (this.PopupModel.IsNegButtonDefault)
            {
                this.NegButtonColor = (Color)Application.Current.Resources["HighlightedColor"];
                this.PosButtonColor = (Color)Application.Current.Resources["FadedColor"];
                return;
            }

            this.NegButtonColor = (Color)Application.Current.Resources["FadedColor"];
            this.PosButtonColor = (Color)Application.Current.Resources["HighlightedColor"];
        }

        public Color NegButtonColor { get; set; }

        /// <summary>
        /// Cancel method of the popup
        /// </summary>
        public ICommand NegCommand
        {
            get
            {
                return new Command(
                  async () =>
                    {
                        this.PopupModel.Result = false;
                        this.PopupModel.ResultText = string.Empty;

                        this.Finish = true;
                        await this.PopPopupAsync();
                    });
            }
        }

        public Color PosButtonColor { get; set; }

        /// <summary>
        /// Ok method of the popup.
        /// </summary>
        public ICommand PosCommand
        {
            get
            {
                return new Command(
                  async () =>
                    {
                        this.PopupModel.Result = true;

                        this.Finish = true;
                        await this.PopPopupAsync();
                    });
            }
        }
    }
}