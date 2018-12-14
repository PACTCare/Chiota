#region References

using System.Windows.Input;
using Chiota.Popups.Base;
using Chiota.Popups.PopupModels;
using Xamarin.Forms;

#endregion

namespace Chiota.Popups.PopupViewModels
{
    public class DialogPopupViewModel : BasePopupViewModel<DialogPopupModel>
    {
        #region Properties

        public Color PosButtonColor { get; set; }

        public Color NegButtonColor { get; set; }

        #endregion

        #region Constructors

        public DialogPopupViewModel() : base()
        {
        }

        public DialogPopupViewModel(DialogPopupModel popupModel) : base(popupModel)
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
        /// Cancel method of the popup.
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

        #endregion
        
    }
}
