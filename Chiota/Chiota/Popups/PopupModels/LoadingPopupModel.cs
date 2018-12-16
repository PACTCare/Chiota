#region References

using Chiota.Popups.Base;

#endregion

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
