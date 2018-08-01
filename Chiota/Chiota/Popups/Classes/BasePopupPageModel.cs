using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Chiota.Annotations;
using Chiota.Extensions;
using Rg.Plugins.Popup.Extensions;
using Rg.Plugins.Popup.Pages;
using Xamarin.Forms;

namespace Chiota.Popups.Classes
{
    public abstract class BasePopupPageModel<T> : INotifyPropertyChanged where T : BasePopupModel
    {
        #region Properties

        //Current navigation, which needed for the popups.
        protected INavigation Navigation { get; private set; }

        //Current popup page.
        protected PopupPage Page { get; private set; }

        //Current popup model.
        public T PopupModel { get; set; }

        //Attention !!! Need to set to true to finish the popup.
        public bool Finish { get; set; }

        #endregion

        #region Constructors

        protected BasePopupPageModel()
        {
        }

        protected BasePopupPageModel(T popupModel)
        {
            PopupModel = popupModel;
        }

        #endregion

        #region Setup

        /// <summary>
        /// Setup the popup page model and provide the needed objects for the popup.
        /// </summary>
        /// <param name="page"></param>
        public void Setup(PopupPage page)
        {
            Page = page;
            Navigation = Page.Navigation;
        }

        #endregion

        #region Init

        /// <summary>
        /// Calling to initialize the page model.
        /// </summary>
        /// /// <param name="data">Passed data of the push.</param>
        public void Init(object data = null)
        {

        }

        #endregion

        #region ViewIsAppearing

        public void OnAppearing(object sender, EventArgs e)
        {
            ViewIsAppearing();
        }

        /// <summary>
        /// Calling if the page will appear
        /// </summary>
        protected virtual void ViewIsAppearing()
        {
        }

        #endregion

        #region ViewIsDisappearing

        public void OnDisappearing(object sender, EventArgs e)
        {
            ViewIsDisappearing();
        }

        /// <summary>
        /// Calling if the page will disappear.
        /// </summary>
        protected virtual void ViewIsDisappearing()
        {
        }

        #endregion

        #region PopupNavigation

        #region DisplayPopupAsync

        /// <summary>
        /// Asynchronously displays a PopupPage to the top of the navigation stack, with optional animation. If the waiting parameter is set to true, the thread will be locked until PopupPageModel.Finish is set to true.
        /// </summary>
        /// <typeparam name="TA">Type of derived class with base of PopupPageModel.</typeparam>
        /// <typeparam name="TB">Type of derived class with base of PopupModel.</typeparam>
        /// <param name="page">The page to display.</param>
        /// <param name="popupModel">The model to pass to the pagemodel which includes the hole data of the popup.</param>
        /// <param name="data">Passing data for init of the page model.</param>
        /// <param name="animated">Whether to animate the display.</param>
        /// <returns>Type of PopupModel</returns>
        public Task<TB> DisplayPopupAsync<TA, TB>(PopupPage page, TB popupModel, object data = null, bool animated = true)
            where TA : BasePopupPageModel<TB>
            where TB : BasePopupModel
        {
            if (!(page.BindingContext is TA popupPageModel)) return null;

            popupPageModel.Init(data);

            page.Appearing += popupPageModel.OnAppearing;
            page.Disappearing += popupPageModel.OnDisappearing;

            return Navigation.DisplayPopupAsync<TA, TB>(page, popupModel, animated);
        }

        #endregion

        #region PushPopupAsync

        /// <summary>
        /// Asynchronously adds a PopupPage to the top of the navigation stack, with optional object as parameter and animation.
        /// </summary>
        /// <param name="page">The page to push.</param>
        /// <param name="data">Passing data for init of the page model.</param>
        /// <param name="animated">Whether to animate the push.</param>
        public Task PushPopupAsync<TA, TB>(PopupPage page, object data = null, bool animated = true)
            where TA : BasePopupPageModel<TB>
            where TB : BasePopupModel
        {
            if (!(page.BindingContext is TA popupPageModel)) return null;

            popupPageModel.Init(data);

            page.Appearing += popupPageModel.OnAppearing;
            page.Disappearing += popupPageModel.OnDisappearing;

            return Navigation.PushPopupAsync(page, animated);
        }

        /// <summary>
        /// Asynchronously adds a PopupPage to the top of the navigation stack, with optional object as parameter and animation.
        /// </summary>
        /// <param name="page">The page to push.</param>
        /// <param name="animated">Whether to animate the push.</param>
        public Task PushPopupAsync(PopupPage page, bool animated = true)
        {
            return Navigation.PushPopupAsync(page, animated);
        }

        #endregion

        #region PopPopupAsync

        /// <summary>
        /// Asynchronously removes the most recent PopupPage from the navigation stack.
        /// </summary>
        /// <param name="animate"></param>
        /// <returns></returns>
        public Task PopPopupAsync(bool animate = true)
        {
            return Navigation.PopPopupAsync(animate);
        }

        #endregion

        #region PopToRootPopupAsync

        /// <summary>
        /// Asynchronously pops all PopupPages off the navigation stack.
        /// </summary>
        /// <param name="animate"></param>
        /// <returns></returns>
        public Task PopToRootPopupAsync(bool animate = true)
        {
            return Navigation.PopAllPopupAsync(animate);
        }

        #endregion

        #region RemovePopupPageAsync

        /// <summary>
        /// Removes the specified PopupPage from the navigation stack.
        /// </summary>
        /// <param name="page"></param>
        /// <param name="animate"></param>
        /// <returns></returns>
        public Task RemovePopupPageAsync(PopupPage page, bool animate = true)
        {
            return Navigation.RemovePopupPageAsync(page, animate);
        }

        #endregion

        #endregion

        #region PropertyChanged

        public event PropertyChangedEventHandler PropertyChanged;

        [NotifyPropertyChangedInvocator]
        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
