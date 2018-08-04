using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Popups.Classes;

namespace Chiota.Popups.PopupModels
{
    public class LoadingPopupModel : BasePopupModel
    {
        #region Attributes

        private bool _isAnimated;

        #endregion

        #region Properties

        public bool IsAnimated
        {
            get => _isAnimated;
            set
            {
                _isAnimated = value;
                OnPropertyChanged(nameof(IsAnimated));
            }
        }

        public string Message { get; set; }

        #endregion

        #region Constructors

        public LoadingPopupModel()
        {
        }

        #endregion
    }
}
