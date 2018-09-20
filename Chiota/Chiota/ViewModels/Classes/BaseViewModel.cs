using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;

using Chiota.Classes;
using Chiota.Extensions;
using Chiota.Popups.Classes;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupPageModels;
using Chiota.Popups.PopupPages;

using Rg.Plugins.Popup.Extensions;
using Rg.Plugins.Popup.Pages;
using Xamarin.Forms;

namespace Chiota.ViewModels.Classes
{
    public abstract class BaseViewModel : INotifyPropertyChanged
    {
        #region Attributes

        private static NavigationAction _navigationAction;
        private static NavigationTyp _navigationTyp;

        /// <summary>
        /// Navigation of the application.
        /// </summary>
        public INavigation Navigation
        {
            get => AppNavigation.NavigationInstance.Navigation;
            set => AppNavigation.NavigationInstance.Navigation = value;
        }

        /// <summary>
        /// Current page which is shown.
        /// </summary>
        protected Page CurrentPage
        {
            get => AppNavigation.NavigationInstance.CurrentPage;
            set => AppNavigation.NavigationInstance.CurrentPage = value;
        }

        /// <summary>
        /// Init object of the current navigation.
        /// </summary>
        protected object InitObject
        {
            get => AppNavigation.NavigationInstance.InitObject;
            set => AppNavigation.NavigationInstance.InitObject = value;
        }

        /// <summary>
        /// Last page which was shown.
        /// </summary>
        protected Page LastPage
        {
            get => AppNavigation.NavigationInstance.LastPage;
            set => AppNavigation.NavigationInstance.LastPage = value;
        }

        /// <summary>
        /// Reverse object of the current navigation.
        /// </summary>
        protected object ReverseObject
        {
            get => AppNavigation.NavigationInstance.ReverseObject;
            set => AppNavigation.NavigationInstance.ReverseObject = value;
        }

        /// <summary>
        /// Root page of the current navigation.
        /// </summary>
        protected Page RootPage
        {
            get => AppNavigation.NavigationInstance.RootPage;
            set => AppNavigation.NavigationInstance.RootPage = value;
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
            page.Appearing += this.OnAppearing;
            page.Disappearing += this.OnDisappearing;
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
            this.CurrentPage = (Page)sender;
            this.Navigation = this.CurrentPage.Navigation;

            // Set the last page for the viewmodel.
            IReadOnlyList<Page> stack = null;
            if (_navigationTyp == NavigationTyp.Modal)
                stack = this.Navigation.ModalStack;
            else
                stack = this.Navigation.NavigationStack;
            this.LastPage = null;
            if (stack.Count > 1)
                for (var i = stack.Count - 1; i > 0; i--)
                {
                    if (stack[i] != this.CurrentPage) continue;
                    this.LastPage = stack[i - 1];
                    break;
                }

            // Set the root page of the current navigation
            var parent = this.CurrentPage.Parent;
            if (parent == null || parent is Application) this.RootPage = this.CurrentPage;
            if (parent is NavigationPage navigation) this.RootPage = navigation.RootPage;

            // Call reverse and init method of the pagemodel.
            if (this.CurrentPage.BindingContext is BaseViewModel viewmodel)
            {
                if (_navigationAction == NavigationAction.Push)
                    viewmodel.Init(this.InitObject);
                else if (_navigationAction == NavigationAction.Pop)
                    viewmodel.Reverse(this.ReverseObject);
            }

            // Clear the param objects of the pagemodel.
            this.InitObject = null;
            this.ReverseObject = null;

            // Clear the navigation enums.
            _navigationAction = NavigationAction.Undefined;
            _navigationTyp = NavigationTyp.Undefined;

            this.ViewIsAppearing();
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
            this.ViewIsDisappearing();
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
        public void InsertPageBefore(Page page, Page before, object data = null)
        {
            // For this action we need to call the push method.
            if (before == this.CurrentPage) return;

            _navigationAction = NavigationAction.Insert;
            _navigationTyp = NavigationTyp.Undefined;

            this.InitObject = data;

            this.Navigation.InsertPageBefore(page, before);
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
        public async Task PushAsync(Page page, object data = null, bool animated = false)
        {
            _navigationAction = NavigationAction.Push;
            _navigationTyp = NavigationTyp.Navigation;

            this.InitObject = data;

            await this.Navigation.PushAsync(page, animated);
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
        public async Task PushModalAsync(Page page, object data = null, bool animated = false)
        {
            _navigationAction = NavigationAction.Push;
            _navigationTyp = NavigationTyp.Modal;

            this.InitObject = data;

            await this.Navigation.PushModalAsync(page, animated);
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
            if (this.LastPage == null) return null;

            _navigationAction = NavigationAction.Pop;
            _navigationTyp = NavigationTyp.Navigation;

            this.ReverseObject = data;

            return await this.Navigation.PopAsync(animated);
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
            if (this.LastPage == null) return null;

            _navigationAction = NavigationAction.Pop;
            _navigationTyp = NavigationTyp.Modal;

            this.ReverseObject = data;

            return await this.Navigation.PopModalAsync(animated);
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
            if (this.RootPage == this.CurrentPage) return;

            _navigationAction = NavigationAction.PopRoot;
            _navigationTyp = NavigationTyp.Undefined;

            this.ReverseObject = data;

            await this.Navigation.PopToRootAsync(animated);
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

            this.Navigation.RemovePage(page);
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
        public Task<TB> DisplayPopupAsync<TA, TB>(PopupPage page, TB popupModel, object data = null, bool animated = true)
            where TA : BasePopupPageModel<TB> where TB : BasePopupModel
        {
            if (!(page.BindingContext is TA popupPageModel)) return null;

            popupPageModel.Setup(page);
            popupPageModel.Init(data);

            page.Appearing += popupPageModel.OnAppearing;
            page.Disappearing += popupPageModel.OnDisappearing;

            return this.Navigation.DisplayPopupAsync<TA, TB>(page, popupModel, animated);
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
          where TA : BasePopupPageModel<TB> where TB : BasePopupModel
        {
            if (!(page.BindingContext is TA popupPageModel)) return null;

            if (popupModel != null)
            {
                // Create new instance to pass the popup model and reset the bindingcontext.
                popupPageModel = (TA)Activator.CreateInstance(typeof(TA), popupModel);
                page.BindingContext = popupPageModel;
            }

            popupPageModel.Init(data);

            page.Appearing += popupPageModel.OnAppearing;
            page.Disappearing += popupPageModel.OnDisappearing;

            return this.Navigation.PushPopupAsync(page, animated);
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
            return this.Navigation.PushPopupAsync(page, animated);
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
            return this.Navigation.PopPopupAsync(animate);
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
            return this.Navigation.PopAllPopupAsync(animate);
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
            return this.Navigation.RemovePopupPageAsync(page, animate);
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
                return new Command(async () => { await this.PopAsync(); });
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
        public async Task DisplayAlertAsync(string title, string message)
        {
            await this.DisplayPopupAsync<AlertPopupPageModel, AlertPopupModel>(new AlertPopupPage(), new AlertPopupModel { Title = title, Message = message });
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
            await this.PushPopupAsync<LoadingPopupPageModel, LoadingPopupModel>(new LoadingPopupPage(), new LoadingPopupModel { Message = text });
        }

        #endregion
        
        #region PropertyChanged

        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>
        /// Will update a specific propertie, which is binded to the ui.
        /// </summary>
        /// <param name="propertyName">
        /// The property name.
        /// </param>
        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}