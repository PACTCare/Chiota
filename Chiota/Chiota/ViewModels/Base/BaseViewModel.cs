#region References

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Extensions;
using Chiota.Popups.Base;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupViewModels;
using Chiota.Popups.PopupViews;
using Chiota.Services.Database;
using Rg.Plugins.Popup.Extensions;
using Rg.Plugins.Popup.Pages;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Base
{
    public abstract class BaseViewModel : INotifyPropertyChanged
    {
        #region Attributes

        private static NavigationAction _navigationAction;
        private static NavigationTyp _navigationTyp;
        private static bool _isInitialized;

        /// <summary>
        /// Navigation of the application.
        /// </summary>
        public INavigation Navigation
        {
            get => AppBase.GetNavigationInstance().Navigation;
            set => AppBase.GetNavigationInstance().Navigation = value;
        }

        /// <summary>
        /// Database of the application.
        /// </summary>
        public DatabaseService Database => AppBase.Database;

        /// <summary>
        /// Current page which is shown.
        /// </summary>
        protected Page CurrentPage
        {
            get => AppBase.GetNavigationInstance().CurrentPage;
            set => AppBase.GetNavigationInstance().CurrentPage = value;
        }

        /// <summary>
        /// Init object of the current navigation.
        /// </summary>
        protected object InitObject
        {
            get => AppBase.GetNavigationInstance().InitObject;
            set => AppBase.GetNavigationInstance().InitObject = value;
        }

        /// <summary>
        /// Last page which was shown.
        /// </summary>
        protected Page LastPage
        {
            get => AppBase.GetNavigationInstance().LastPage;
            set => AppBase.GetNavigationInstance().LastPage = value;
        }

        /// <summary>
        /// Reverse object of the current navigation.
        /// </summary>
        protected object ReverseObject
        {
            get => AppBase.GetNavigationInstance().ReverseObject;
            set => AppBase.GetNavigationInstance().ReverseObject = value;
        }

        /// <summary>
        /// Root page of the current navigation.
        /// </summary>
        protected Page RootPage
        {
            get => AppBase.GetNavigationInstance().RootPage;
            set => AppBase.GetNavigationInstance().RootPage = value;
        }

        #endregion

        #region Enum

        #region NavigationAction

        private enum NavigationAction
        {
            Undefined,
            Insert,
            Push,
            Pop,
            PopRoot,
            Remove
        }

        #endregion

        #region NavigationTyp

        private enum NavigationTyp
        {
            Undefined,
            Navigation,
            Modal
        }

        #endregion

        #endregion

        #region Constructors

        protected BaseViewModel()
        {
            _isInitialized = false;
        }

        #endregion

        #region Setup

        /// <summary>
        /// Will setup the page model for the usage.
        /// </summary>
        /// <param name="page">
        /// Page of the viewmodel.
        /// </param>
        public void Setup(Page page)
        {
            // Activate appearing events for the page model.
            page.Appearing += OnAppearing;
            page.Disappearing += OnDisappearing;

            // Call reverse and init method of the pagemodel.
            if (page.BindingContext is BaseViewModel viewmodel)
                if (!_isInitialized)
                {
                    viewmodel.Init(InitObject);
                    _isInitialized = true;
                }

            // Clear the param objects of the pagemodel.
            InitObject = null;
        }

        #endregion

        #region Init

        /// <summary>
        /// Calling to initialize the page model.
        /// </summary>
        /// /// 
        /// <param name="data">
        /// Passed data of the push.
        /// </param>
        public virtual void Init(object data = null)
        {
        }

        #endregion

        #region Reverse

        /// <summary>
        /// Calling to reverse initialize the page model.
        /// </summary>
        /// <param name="data">
        /// Passed data of the pop.
        /// </param>
        public virtual void Reverse(object data = null)
        {
        }

        #endregion

        #region ViewIsAppearing

        /// <summary>
        /// Will be called, when the page appears.
        /// </summary>
        /// <param name="sender">
        /// </param>
        /// <param name="e">
        /// </param>
        private void OnAppearing(object sender, EventArgs e)
        {
            // Set current page and navigation.
            CurrentPage = (Page)sender;
            Navigation = CurrentPage.Navigation;

            // Set the last page for the viewmodel.
            IReadOnlyList<Page> stack = null;
            if (_navigationTyp == NavigationTyp.Modal)
                stack = Navigation.ModalStack;
            else
                stack = Navigation.NavigationStack;
            LastPage = null;
            if (stack.Count > 1)
                for (var i = stack.Count - 1; i > 0; i--)
                {
                    if (stack[i] != CurrentPage) continue;
                    LastPage = stack[i - 1];
                    break;
                }

            // Set the root page of the current navigation
            var parent = CurrentPage.Parent;
            if (parent == null || parent is Application) RootPage = CurrentPage;
            if (parent is NavigationPage navigation) RootPage = navigation.RootPage;

            // Call reverse and init method of the pagemodel.
            if (CurrentPage.BindingContext is BaseViewModel viewmodel)
            {
                if (_navigationAction == NavigationAction.Pop)
                    viewmodel.Reverse(ReverseObject);
            }

            // Clear the param objects of the pagemodel.
            ReverseObject = null;

            // Clear the navigation enums.
            _navigationAction = NavigationAction.Undefined;
            _navigationTyp = NavigationTyp.Undefined;

            ViewIsAppearing();
        }

        /// <summary>
        /// Calling if the page will appearing.
        /// </summary>
        protected virtual void ViewIsAppearing()
        {
        }

        #endregion

        #region ViewIsDisappearing

        /// <summary>
        /// Will be called, when the page disappears.
        /// </summary>
        /// <param name="sender">
        /// </param>
        /// <param name="e">
        /// </param>
        private void OnDisappearing(object sender, EventArgs e)
        {
            ViewIsDisappearing();
        }

        /// <summary>
        /// Calling if the page will disappearing.
        /// </summary>
        protected virtual void ViewIsDisappearing()
        {
        }

        #endregion

        #region Navigation

        #region InsertPageBefore

        /// <summary>
        /// Inserts a page in the navigation stack before an existing page in the stack.
        /// </summary>
        /// <param name="page">
        /// The page to add.
        /// </param>
        /// <param name="before">
        /// The existing page, before which page will be inserted.
        /// </param>
        /// <param name="data">
        /// The parameter which pass to the pagemodel.
        /// </param>
        public void InsertPageBefore<T>(Page before, object data = null) where T : Page
        {
            // For this action we need to call the push method.
            if (before == CurrentPage) return;

            _navigationAction = NavigationAction.Insert;
            _navigationTyp = NavigationTyp.Undefined;

            InitObject = data;
            var page = (T)Activator.CreateInstance(typeof(T));

            Navigation.InsertPageBefore(page, before);
        }

        #endregion

        #region PushAsync

        /// <summary>
        /// Asynchronously adds a Xamarin.Forms.Page to the top of the navigation stack, with optional object as parameter and animation.
        /// </summary>
        /// <param name="page">
        /// The page to push.
        /// </param>
        /// <param name="data">
        /// The parameter which given to the pagemodel.
        /// </param>
        /// <param name="animated">
        /// Whether to animate the push.
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public async Task PushAsync<T>(object data = null, bool animated = false) where T : Page
        {
            _navigationAction = NavigationAction.Push;
            _navigationTyp = NavigationTyp.Navigation;

            InitObject = data;
            var page = (T)Activator.CreateInstance(typeof(T));

            await Navigation.PushAsync(page, animated);
        }

        /// <summary>
        /// Asynchronously adds a Xamarin.Forms.Page to the top of the navigation stack, with optional object as parameter and animation.
        /// </summary>
        /// <param name="page">
        /// The page to push.
        /// </param>
        /// <param name="data">
        /// The parameter which given to the pagemodel.
        /// </param>
        /// <param name="animated">
        /// Whether to animate the push.
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public async Task PushModalAsync<T>(object data = null, bool animated = false) where T: Page
        {
            _navigationAction = NavigationAction.Push;
            _navigationTyp = NavigationTyp.Modal;

            InitObject = data;
            var page = (T)Activator.CreateInstance(typeof(T));

            await Navigation.PushModalAsync(page, animated);
        }

        #endregion

        #region PopAsync

        /// <summary>
        /// Asynchronously removes the most recent Xamarin.Forms.Page from the navigation stack.
        /// </summary>
        /// <param name="data">
        /// The parameter which pass to the pagemodel.
        /// </param>
        /// <param name="animated">
        /// Whether to animate the pop.
        /// </param>
        /// <returns>
        /// The Xamarin.Forms.Page that had been at the top of the navigation stack.
        /// </returns>
        public async Task<Page> PopAsync(object data = null, bool animated = false)
        {
            if (LastPage == null) return null;

            _navigationAction = NavigationAction.Pop;
            _navigationTyp = NavigationTyp.Navigation;

            ReverseObject = data;

            return await Navigation.PopAsync(animated);
        }

        /// <summary>
        /// Asynchronously dismisses the most recent modally presented Xamarin.Forms.Page.
        /// </summary>
        /// <param name="data">
        /// The parameter which pass to the pagemodel.
        /// </param>
        /// <param name="animated">
        /// Whether to animate the pop.
        /// </param>
        /// <returns>
        /// The Xamarin.Forms.Page that had been at the top of the navigation stack.
        /// </returns>
        public async Task<Page> PopModalAsync(object data = null, bool animated = false)
        {
            if (LastPage == null) return null;

            _navigationAction = NavigationAction.Pop;
            _navigationTyp = NavigationTyp.Modal;

            ReverseObject = data;

            return await Navigation.PopModalAsync(animated);
        }

        #endregion

        #region PopToRootAsync

        /// <summary>
        /// Asynchronously pops all but the root Xamarin.Forms.Page off the navigation stack.
        /// </summary>
        /// <param name="data">
        /// The parameter which pass to the pagemodel.
        /// </param>
        /// <param name="animated">
        /// Whether to animate the pop.
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public async Task PopToRootAsync(object data = null, bool animated = false)
        {
            if (RootPage == CurrentPage) return;

            _navigationAction = NavigationAction.PopRoot;
            _navigationTyp = NavigationTyp.Undefined;

            ReverseObject = data;

            await Navigation.PopToRootAsync(animated);
        }

        #endregion

        #region RemovePage

        /// <summary>
        /// Removes the specified page from the navigation stack.
        /// </summary>
        /// <param name="page">
        /// The page to remove.
        /// </param>
        public void RemovePage(Page page)
        {
            _navigationAction = NavigationAction.Remove;
            _navigationTyp = NavigationTyp.Undefined;

            Navigation.RemovePage(page);
        }

        #endregion

        #endregion

        #region PopupNavigation

        #region DisplayPopupAsync

        /// <summary>
        /// Asynchronously displays a PopupPage to the top of the navigation stack, with optional animation. If the waiting parameter is set to true, the thread will be locked until PopupPageModel.Finish is set to true.
        /// </summary>
        /// <typeparam name="TA">
        /// Type of derived class with base of PopupPageModel.
        /// </typeparam>
        /// <typeparam name="TB">
        /// Type of derived class with base of PopupModel.
        /// </typeparam>
        /// <param name="page">
        /// The page to display.
        /// </param>
        /// <param name="popupModel">
        /// The model to pass to the pagemodel which includes the hole data of the popup.
        /// </param>
        /// <param name="data">
        /// Passing data for init of the page model.
        /// </param>
        /// <param name="animated">
        /// Whether to animate the display.
        /// </param>
        /// <returns>
        /// Type of PopupModel
        /// </returns>
        public Task<TB> DisplayPopupAsync<TA, TB>(PopupPage page, TB popupModel = null, object data = null, bool animated = true)
            where TA : BasePopupViewModel<TB> where TB : BasePopupModel
        {
            //Not needed, because it is already a part of the popup extension.
            //popupPageModel.Setup(page, data);

            return Navigation.DisplayPopupAsync<TA, TB>(page, popupModel, animated);
        }

        #endregion

        #region PushPopupAsync

        /// <summary>
        /// Asynchronously adds a PopupPage to the top of the navigation stack, with optional object as parameter and animation.
        /// </summary>
        /// <param name="page">
        /// The page to push.
        /// </param>
        /// <param name="popupModel">
        /// </param>
        /// <param name="data">
        /// Passing data for init of the page model.
        /// </param>
        /// <param name="animated">
        /// Whether to animate the push.
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public Task PushPopupAsync<TA, TB>(PopupPage page, BasePopupModel popupModel = null, object data = null, bool animated = true)
          where TA : BasePopupViewModel<TB> where TB : BasePopupModel
        {
            if (!(page.BindingContext is TA popupPageModel)) return null;

            if (popupModel != null)
            {
                // Create new instance to pass the popup model and reset the bindingcontext.
                popupPageModel = (TA)Activator.CreateInstance(typeof(TA), popupModel);
                page.BindingContext = popupPageModel;
            }

            popupPageModel.Setup(page, data);

            return Navigation.PushPopupAsync(page, animated);
        }

        /// <summary>
        /// Asynchronously adds a PopupPage to the top of the navigation stack, with optional object as parameter and animation.
        /// </summary>
        /// <param name="page">
        /// The page to push.
        /// </param>
        /// <param name="animated">
        /// Whether to animate the push.
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public Task PushPopupAsync(PopupPage page, bool animated = true)
        {
            return Navigation.PushPopupAsync(page, animated);
        }

        #endregion

        #region PopPopupAsync

        /// <summary>
        /// Asynchronously removes the most recent PopupPage from the navigation stack.
        /// </summary>
        /// <param name="animate">
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public Task PopPopupAsync(bool animate = true)
        {
            return Navigation.PopPopupAsync(animate);
        }


        #endregion

        #region PopToRootPopup

        /// <summary>
        /// Asynchronously pops all PopupPages off the navigation stack.
        /// </summary>
        /// <param name="animate">
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public Task PopToRootPopupAsync(bool animate = true)
        {
            return Navigation.PopAllPopupAsync(animate);
        }

        #endregion

        #region RemovePopupPageAsync

        /// <summary>
        /// Removes the specified PopupPage from the navigation stack.
        /// </summary>
        /// <param name="page">
        /// </param>
        /// <param name="animate">
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public Task RemovePopupPageAsync(PopupPage page, bool animate = true)
        {
            return Navigation.RemovePopupPageAsync(page, animate);
        }

        #endregion

        #endregion
        
        #region Commands

        #region Back

        /// <summary>
        /// Default command for back button with simple pop.
        /// </summary>
        public ICommand BackCommand
        {
            get
            {
                return new Command(async () => { await PopAsync(); });
            }
        }

        #endregion

        #endregion

        #region Methods

        /// <summary>
        /// The display alert async.
        /// </summary>
        /// <param name="title">
        /// The title.
        /// </param>
        /// <param name="message">
        /// The message.
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public async Task<AlertPopupModel> DisplayAlertAsync(string title, string message, bool isNegVisible = false, bool isNegDefault = true)
        {
            var alert = new AlertPopupModel()
            {
                Title = title,
                Message = message,
                IsNegButtonVisible = isNegVisible,
                IsNegButtonDefault = isNegDefault
            };

            return await DisplayPopupAsync<AlertPopupViewModel, AlertPopupModel>(new AlertPopupView(), alert);
        }

        /// <summary>
        /// The display loading spinner async.
        /// </summary>
        /// <param name="text">
        /// The text.
        /// </param>
        /// <returns>
        /// The <see cref="Task"/>.
        /// </returns>
        public async Task PushLoadingSpinnerAsync(string text)
        {
            await PushPopupAsync<LoadingPopupViewModel, LoadingPopupModel>(new LoadingPopupView(), new LoadingPopupModel { Message = text });
        }

        #endregion
        
        #region PropertyChanged

        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>
        /// Will update a specific properties, which are binded to the ui.
        /// </summary>
        /// <param name="propertyName">
        /// The property name.
        /// </param>
        protected void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}