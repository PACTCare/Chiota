#region Rerferences

using System.Windows.Input;
using Chiota.Popups.Base;
using Chiota.Popups.PopupModels;
using Xamarin.Forms;

#endregion

namespace Chiota.Popups.PopupViewModels
{
    public class AlertPopupViewModel : BasePopupViewModel<AlertPopupModel>
    {
        #region Properties

        /// <summary>
        /// Gets or sets the neg button text color.
        /// </summary>
        public Color NegButtonColor { get; set; }

        /// <summary>
        /// Gets or sets the pos button text color.
        /// </summary>
        public Color PosButtonColor { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="AlertPopupViewModel"/> class.
        /// </summary>
        public AlertPopupViewModel() : base()
        {
        }

        public AlertPopupViewModel(AlertPopupModel popupModel) : base(popupModel)
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

        #endregion

        #region Commands

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

        #endregion
    }
}