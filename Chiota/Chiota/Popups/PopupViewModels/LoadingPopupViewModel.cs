using Chiota.Popups.Base;
using Chiota.Popups.PopupModels;

namespace Chiota.Popups.PopupViewModels
{
    public class LoadingPopupViewModel : BasePopupViewModel<LoadingPopupModel>
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

        public LoadingPopupViewModel() : base(new LoadingPopupModel())
        {
            //Set the message visible, if there is any message.
            if (!string.IsNullOrEmpty(PopupModel.Message))
                PopupModel.IsMessageVisible = true;
        }

        public LoadingPopupViewModel(LoadingPopupModel popupModel) : base(popupModel)
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
