using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Popups.Classes;
using Rg.Plugins.Popup.Pages;
using Rg.Plugins.Popup.Services;
using Xamarin.Forms;

namespace Chiota.Extensions
{
    using Chiota.Popups.PopupModels;
    using Chiota.Popups.PopupPageModels;
    using Chiota.Popups.PopupPages;

    public static class PopupNavigationExtension
    {
        #region Methods

        #region DisplayAsync

        /// <summary>
        /// Asynchronously displays a <see cref="T:PopupPage" /> to the top of the navigation stack, with optional animation. If the waiting parameter is set to true, the thread will be locked until <see cref="T:PopupPageModel.Finish"/> is set to true.
        /// </summary>
        /// <typeparam name="TA">Type of derived class with base of <see cref="T:BasePopupPageModel"/>.</typeparam>
        /// <typeparam name="TB">Type of derived class with base of <see cref="T:BasePopupModel"/>.</typeparam>
        /// <param name="sender">Method can directly used by the native navigation of Xamarin.</param>
        /// <param name="page">The page to display.</param>
        /// <param name="popupModel">The model to pass to the pagemodel which includes the hole data of the popup.</param>
        /// <param name="data">Passing data for init of the page model.</param>
        /// <param name="animate">Whether to animate the display.</param>
        /// <returns>Type of PopupModel</returns>
        public static async Task<TB> DisplayPopupAsync<TA, TB>(this INavigation sender, PopupPage page, TB popupModel = null, object data = null, bool animate = true)
            where TA : BasePopupPageModel<TB>
            where TB : BasePopupModel
        {
            if (!(page.BindingContext is TA)) return null;

            TA popupPageModel;

            //Create new instance of the pagemodel
            if (popupModel == null)
                popupPageModel = (TA)Activator.CreateInstance(typeof(TA));
            else
                popupPageModel = (TA)Activator.CreateInstance(typeof(TA), popupModel);

            popupPageModel.Finish = false;
            page.BindingContext = popupPageModel;

            //Push the page on the top of the navigationstack
            await PopupNavigation.Instance.PushAsync(page, animate);

            while (!popupPageModel.Finish)
                await Task.Delay(TimeSpan.FromMilliseconds(100));

            //Return result of the popup
            return popupPageModel.PopupModel;
        }

        #endregion

        #endregion
    }
}
