using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Popups.Classes;
using Chiota.Resources.Localizations;

namespace Chiota.Popups.PopupModels
{
    public class DialogPopupModel : BasePopupModel
    {
        #region Properties

        public string Title { get; set; }
        public string Placeholder { get; set; }
        public bool IsPassword { get; set; }
        public bool Result { get; set; }
        public string ResultText { get; set; }
        public string PosButtonText { get; set; }
        public string NegButtonText { get; set; }
        public bool IsNegButtonDefault { get; set; }

        #endregion

        #region Constructors

        public DialogPopupModel()
        {
            //Set default attributes
            PosButtonText = AppResources.DlgOk;
            NegButtonText = AppResources.DlgCancel;
            IsPassword = false;
        }

        #endregion
    }
}
