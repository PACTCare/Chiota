using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Popups.Classes;

namespace Chiota.Popups.PopupModels
{
    public class AlertPopupModel : BasePopupModel
    {
        #region Properties

        public string Title { get; set; }
        public string Message { get; set; }
        public bool Result { get; set; }
        public bool IsTitleVisible { get; set; }
        public bool IsNegButtonVisible { get; set; }
        public bool IsNegButtonDefault { get; set; }
        public string PosButtonText { get; set; }
        public string NegButtonText { get; set; }

        #endregion

        #region Constructors

        public AlertPopupModel()
        {
            //Set default attributes
            //Normaly we should use resx files to handle dialogs and text,
            //this is also important for switching language, TODO
            PosButtonText = "Ok";   //AppResources.DlgOk;
            NegButtonText = "Cancel";   //AppResources.DlgCancel;
        }

        #endregion
    }
}
