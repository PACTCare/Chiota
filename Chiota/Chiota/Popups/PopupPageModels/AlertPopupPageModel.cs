namespace Chiota.Popups.PopupPageModels
{
    using System.Windows.Input;

    using Chiota.Popups.Classes;
    using Chiota.Popups.PopupModels;

    using Xamarin.Forms;

    /// <summary>
    /// The alert popup page model.
    /// </summary>
    public class AlertPopupPageModel : BasePopupPageModel<AlertPopupModel>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlertPopupPageModel"/> class.
        /// </summary>
        public AlertPopupPageModel()
          : base()
        {
        }

        public AlertPopupPageModel(AlertPopupModel popupModel)
          : base(popupModel)
        {
            if (!string.IsNullOrEmpty(PopupModel.Title))
            {
                PopupModel.IsTitleVisible = true;
            }

            if (PopupModel.IsNegButtonDefault)
            {
                NegButtonColor = (Color)Application.Current.Resources["HighlightedColor"];
                PosButtonColor = (Color)Application.Current.Resources["FadedColor"];
                return;
            }

            NegButtonColor = (Color)Application.Current.Resources["FadedColor"];
            PosButtonColor = (Color)Application.Current.Resources["HighlightedColor"];
        }

        /// <summary>
        /// Gets or sets the neg button text color.
        /// </summary>
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
                        PopupModel.Result = false;

                        Finish = true;
                        await PopPopupAsync();
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
                        PopupModel.Result = true;

                        Finish = true;
                        await PopPopupAsync();
                    });
            }
        }
    }
}