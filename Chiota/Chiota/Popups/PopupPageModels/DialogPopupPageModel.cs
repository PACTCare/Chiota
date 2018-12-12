using Chiota.Popups.Base;

namespace Chiota.Popups.PopupPageModels
{
    using System.Windows.Input;
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
            if (PopupModel.IsNegButtonDefault)
            {
                NegButtonColor = (Color)Application.Current.Resources["HighlightedColor"];
                PosButtonColor = (Color)Application.Current.Resources["FadedColor"];
                return;
            }

            NegButtonColor = (Color)Application.Current.Resources["FadedColor"];
            PosButtonColor = (Color)Application.Current.Resources["HighlightedColor"];
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
                        PopupModel.Result = false;
                        PopupModel.ResultText = string.Empty;

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