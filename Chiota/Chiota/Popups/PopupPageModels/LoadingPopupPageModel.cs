using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Popups.Classes;
using Chiota.Popups.PopupModels;
using Xamarin.Forms;

namespace Chiota.Popups.PopupPageModels
{
    public class LoadingPopupPageModel : BasePopupPageModel<LoadingPopupModel>
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

        #endregion

        #region Constructors

        public LoadingPopupPageModel() : base(new LoadingPopupModel())
        {
            //Set the message visible, if there is any message.
            if (!string.IsNullOrEmpty(PopupModel.Message))
                PopupModel.IsMessageVisible = true;
        }

        public LoadingPopupPageModel(LoadingPopupModel popupModel) : base(popupModel)
        {
            //Set the message visible, if there is any message.
            if (!string.IsNullOrEmpty(PopupModel.Message))
                PopupModel.IsMessageVisible = true;
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            IsAnimated = true;

            base.ViewIsAppearing();
        }

        #endregion

        #region ViewIsDisappearing

        protected override void ViewIsDisappearing()
        {
            IsAnimated = false;

            base.ViewIsDisappearing();
        }

        #endregion
    }
}
