#region Rerferences

using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Popups.Base;
using Chiota.Popups.PopupModels;

using Xamarin.Forms;

#endregion

namespace Chiota.Popups.PopupPageModels
{
    public class AlertPopupPageModel : BasePopupPageModel<AlertPopupModel>
    {
        #region Attributes

        private bool _isPosButtonFocused;

        #endregion

        #region Properties

        /// <summary>
        /// Gets or sets the neg button text color.
        /// </summary>
        public Color NegButtonColor { get; set; }

        /// <summary>
        /// Gets or sets the pos button text color.
        /// </summary>
        public Color PosButtonColor { get; set; }

        /// <summary>
        /// Gets or sets the focus of the pos button.
        /// </summary>
        public bool IsPosButtonFocused
        {
            get => _isPosButtonFocused;
            set
            {
                _isPosButtonFocused = value;
                OnPropertyChanged(nameof(IsPosButtonFocused));
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="AlertPopupPageModel"/> class.
        /// </summary>
        public AlertPopupPageModel() : base()
        {
        }

        public AlertPopupPageModel(AlertPopupModel popupModel) : base(popupModel)
        {
            if (!string.IsNullOrEmpty(PopupModel.Title))
            {
                PopupModel.IsTitleVisible = true;
            }

            if (PopupModel.IsNegButtonDefault)
            {
                NegButtonColor = (Color)Application.Current.Resources["HighlightedColor"];
                PosButtonColor = (Color)Application.Current.Resources["FadedColor"];
                return;
            }

            NegButtonColor = (Color)Application.Current.Resources["FadedColor"];
            PosButtonColor = (Color)Application.Current.Resources["HighlightedColor"];
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            Device.BeginInvokeOnMainThread(async () =>
            {
                //Focus the entry.
                await Task.Delay(TimeSpan.FromMilliseconds(500));
                IsPosButtonFocused = true;
            });
        }

        #endregion

        #region Commands

        /// <summary>
        /// Ok method of the popup.
        /// </summary>
        public ICommand PosCommand
        {
            get
            {
                return new Command(
                    async () =>
                    {
                        PopupModel.Result = true;

                        Finish = true;
                        await PopPopupAsync();
                    });
            }
        }

        /// <summary>
        /// Cancel method of the popup
        /// </summary>
        public ICommand NegCommand
        {
            get
            {
                return new Command(
                    async () =>
                    {
                        PopupModel.Result = false;

                        Finish = true;
                        await PopPopupAsync();
                    });
            }
        }

        #endregion
    }
}