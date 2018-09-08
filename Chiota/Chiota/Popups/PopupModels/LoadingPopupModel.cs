using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Popups.Classes;

namespace Chiota.Popups.PopupModels
{
    public class LoadingPopupModel : BasePopupModel
    {
        #region Properties

        public string Message { get; set; }
        public bool IsMessageVisible { get; set; }

        #endregion

        #region Constructors

        public LoadingPopupModel()
        {
            //Set the default message.
            Message = "Loading";
        }

        #endregion
    }
}
