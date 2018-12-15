#region References

using Chiota.Popups.Base;
using Chiota.Resources.Localizations;

#endregion

namespace Chiota.Popups.PopupModels
{
    public class AlertPopupModel : BasePopupModel
    {
        #region Properties

        public bool IsNegButtonDefault { get; set; }

        public bool IsNegButtonVisible { get; set; }

        public bool IsTitleVisible { get; set; }

        public string Message { get; set; }

        public string NegButtonText { get; set; }

        public string PosButtonText { get; set; }

        public bool Result { get; set; }

        public string Title { get; set; }

        #endregion

        #region Constructors

        public AlertPopupModel()
        {
            // Set default attributes
            PosButtonText = AppResources.DlgOk;
            NegButtonText = AppResources.DlgCancel;
        }

        #endregion
    }
}