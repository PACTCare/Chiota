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
        #region Constructors

        public LoadingPopupPageModel() : base()
        {
            PopupModel = new LoadingPopupModel();
        }

        public LoadingPopupPageModel(LoadingPopupModel popupModel) : base(popupModel)
        {
        }

        #endregion

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            PopupModel.IsAnimated = true;
        }

        protected override void ViewIsDisappearing()
        {
            PopupModel.IsAnimated = false;

            base.ViewIsDisappearing();
        }
    }
}
