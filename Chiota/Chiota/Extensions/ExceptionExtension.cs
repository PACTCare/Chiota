using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Classes;
using Chiota.Exceptions;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupPageModels;
using Chiota.Popups.PopupPages;

namespace Chiota.Extensions
{
    public static class ExceptionExtension
    {
        #region Methods

        #region GetAlert

        /// <summary>
        /// Get an alert object of the exception to show the informations of the exception in a popup.
        /// </summary>
        /// <param name="exception">Exception object, where we get the informations, we will write into the popup.</param>
        /// <param name="isNegative">Is the negative button visible.</param>
        /// <param name="isNegativeDefault">Is the negative button emphasize, means a specific color.</param>
        /// <returns></returns>
        public static AlertPopupModel GetAlert(this BaseException exception, bool isNegative = false, bool isNegativeDefault = false)
        {
            //Create the alert popup model.
            var alert = new AlertPopupModel()
            {
                Title = exception.Title,
                Message = exception.Message,
                IsNegButtonVisible = isNegative,
                IsNegButtonDefault = isNegativeDefault
            };

            if (!string.IsNullOrEmpty(exception.Detail))
                alert.Message = exception.Detail;

            return alert;
        }

        #endregion

        #region ShowAlert

        /// <summary>
        /// Show an alert popup with the exception as source.
        /// </summary>
        /// <param name="exception">Exception object, where we get the informations, we will write into the popup.</param>
        /// <param name="isNegative">Is the negative button visible.</param>
        /// <param name="isNegativeDefault">Is the negative button emphasize, means a specific color.</param>
        /// <returns></returns>
        public static async Task ShowAlertAsync(this BaseException exception, bool isNegative = false, bool isNegativeDefault = false)
        {
            //Create the alert popup model.
            var alert = new AlertPopupModel()
            {
                Title = exception.Title,
                Message = exception.Message,
                IsNegButtonVisible = isNegative,
                IsNegButtonDefault = isNegativeDefault
            };

            if (!string.IsNullOrEmpty(exception.Detail))
                alert.Message = exception.Detail;

            //Get the current navigation instance and show the popup.
            var navigation = AppNavigation.NavigationInstance.CurrentPage.Navigation;
            await navigation.DisplayPopupAsync<AlertPopupPageModel, AlertPopupModel>(new AlertPopupPage(), alert);
        }

        #endregion

        #endregion
    }
}
