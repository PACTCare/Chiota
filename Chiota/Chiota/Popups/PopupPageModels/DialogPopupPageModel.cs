using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Popups.Classes;
using Chiota.Popups.PopupModels;
using Xamarin.Forms;

namespace Chiota.Popups.PopupPageModels
{
    public class DialogPopupPageModel : BasePopupPageModel<DialogPopupModel>
    {
        #region Properties

        public Color NegButtonTextColor { get; set; }
        public Color PosButtonTextColor { get; set; }

        #endregion

        #region Constructors

        public DialogPopupPageModel() : base()
        {

        }

        public DialogPopupPageModel(DialogPopupModel popupModel) : base(popupModel)
        {
            if (PopupModel.IsNegButtonDefault)
            {
                NegButtonTextColor = (Color)Application.Current.Resources["HighlightedTextColor"];
                PosButtonTextColor = (Color)Application.Current.Resources["FadedTextColor"];
                return;
            }

            NegButtonTextColor = (Color)Application.Current.Resources["FadedTextColor"];
            PosButtonTextColor = (Color)Application.Current.Resources["HighlightedTextColor"];
        }

        #endregion

        #region NegCommand

        // ---------------------------------------------------------------------
        /// <summary>
        /// Cancel method of the popup
        /// </summary>
        // ---------------------------------------------------------------------
        public ICommand NegCommand
        {
            get
            {
                return new Command(async () =>
                {
                    PopupModel.Result = false;
                    PopupModel.ResultText = string.Empty;

                    Finish = true;
                    await PopPopupAsync();
                });
            }
        }

        #endregion

        #region PosCommand

        // ---------------------------------------------------------------------
        /// <summary>
        /// Ok method of the popup.
        /// </summary>
        // ---------------------------------------------------------------------
        public ICommand PosCommand
        {
            get
            {
                return new Command(async () =>
                {
                    PopupModel.Result = true;

                    Finish = true;
                    await PopPopupAsync();
                });
            }
        }

        #endregion
    }
}
