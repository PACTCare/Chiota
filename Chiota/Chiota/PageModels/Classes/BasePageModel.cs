using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Classes;
using Chiota.Extensions;
using Chiota.Popups.Classes;
using Rg.Plugins.Popup.Extensions;
using Rg.Plugins.Popup.Pages;
using Xamarin.Forms;

namespace Chiota.PageModels.Classes
{
    public abstract class BasePageModel : INotifyPropertyChanged
    {
        #region Attributes

        private static NavigationAction _navigationAction;
        private static NavigationTyp _navigationTyp;

        private bool isBusy;

        #endregion

        #region Properties

        //Navigation of the application.
        public INavigation Navigation
        {
            get => AppNavigation.NavigationInstance.Navigation;
            set => AppNavigation.NavigationInstance.Navigation = value;
        }

        //Current page which is shown.
        protected Page CurrentPage
        {
            get => AppNavigation.NavigationInstance.CurrentPage;
            set => AppNavigation.NavigationInstance.CurrentPage = value;
        }

        //Last page which was shown.
        protected Page LastPage
        {
            get => AppNavigation.NavigationInstance.LastPage;
            set => AppNavigation.NavigationInstance.LastPage = value;
        }

        //Root page of the current navigation.
        protected Page RootPage
        {
            get => AppNavigation.NavigationInstance.RootPage;
            set => AppNavigation.NavigationInstance.RootPage = value;
        }

        //Init object of the current navigation.
        protected object InitObject
        {
            get => AppNavigation.NavigationInstance.InitObject;
            set => AppNavigation.NavigationInstance.InitObject = value;
        }

        //Reverse object of the current navigation.
        protected object ReverseObject
        {
            get => AppNavigation.NavigationInstance.ReverseObject;
            set => AppNavigation.NavigationInstance.ReverseObject = value;
        }

        public bool IsBusy
        {
            get => this.isBusy;
            set
            {
                this.isBusy = value;
                this.OnPropertyChanged();
            }
        }

        #endregion

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

        #region Constructors

        /// <summary>
        /// Default constructor.
        /// </summary>
        protected BasePageModel()
        {
        }

        #endregion

        #region Methods

        #region Setup

        /// <summary>
        /// Will setup the page model for the usage.
        /// </summary>
        /// <param name="page">Page of the viewmodel.</param>
        public void Setup(Page page)
        {
            //Activate appearing events for the page model.
            page.Appearing += OnAppearing;
            page.Disappearing += OnDisappearing;
        }

        #endregion

        #region Init

        /// <summary>
        /// Calling to initialize the page model.
        /// </summary>
        /// /// <param name="data">Passed data of the push.</param>
        public virtual void Init(object data = null)
        {

        }

        #endregion

        #region Reverse

        /// <summary>
        /// Calling to reverse initialize the page model.
        /// </summary>
        /// <param name="data">Passed data of the pop.</param>
        public virtual void Reverse(object data = null)
        {

        }

        #endregion

        #region ViewIsAppearing

        /// <summary>
        /// Will be called, when the page appears.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnAppearing(object sender, EventArgs e)
        {
            //Set current page and navigation.
            CurrentPage = (Page)sender;
            Navigation = CurrentPage.Navigation;

            //Set the last page for the viewmodel.
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

            //Set the root page of the current navigation
            var parent = CurrentPage.Parent;
            if (parent == null || parent is Application)
                RootPage = CurrentPage;
            if (parent is NavigationPage navigation)
                RootPage = navigation.RootPage;

            //Call reverse and init method of the pagemodel.
            if (CurrentPage.BindingContext is BasePageModel viewmodel)
            {
                if (_navigationAction == NavigationAction.Push)
                    if (InitObject != null)
                        viewmodel.Init(InitObject);
                    else if (_navigationAction == NavigationAction.Pop)
                        if (ReverseObject != null)
                            viewmodel.Reverse(ReverseObject);
            }

            //Clear the param objects of the pagemodel.
            InitObject = null;
            ReverseObject = null;

            //Clear the navigation enums.
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
        /// <param name="sender"></param>
        /// <param name="e"></param>
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
        /// <param name="page">The page to add.</param>
        /// <param name="before">The existing page, before which page will be inserted.</param>
        /// <param name="data">The parameter which pass to the pagemodel.</param>
        public void InsertPageBefore(Page page, Page before, object data = null)
        {
            //For this action we need to call the push method.
            if (before == CurrentPage) return;

            _navigationAction = NavigationAction.Insert;
            _navigationTyp = NavigationTyp.Undefined;

            InitObject = data;

            Navigation.InsertPageBefore(page, before);
        }

        #endregion

        #region PushAsync

        /// <summary>
        /// Asynchronously adds a Xamarin.Forms.Page to the top of the navigation stack, with optional object as parameter and animation.
        /// </summary>
        /// <param name="page">The page to push.</param>
        /// <param name="data">The parameter which given to the pagemodel.</param>
        /// <param name="animated">Whether to animate the push.</param>
        public async Task PushAsync(Page page, object data = null, bool animated = false)
        {
            _navigationAction = NavigationAction.Push;
            _navigationTyp = NavigationTyp.Navigation;

            InitObject = data;

            await Navigation.PushAsync(page, animated);
        }

        #endregion

        #region PushModalAsync

        /// <summary>
        /// Asynchronously adds a Xamarin.Forms.Page to the top of the navigation stack, with optional object as parameter and animation.
        /// </summary>
        /// <param name="page">The page to push.</param>
        /// <param name="data">The parameter which given to the pagemodel.</param>
        /// <param name="animated">Whether to animate the push.</param>
        public async Task PushModalAsync(Page page, object data = null, bool animated = false)
        {
            _navigationAction = NavigationAction.Push;
            _navigationTyp = NavigationTyp.Modal;

            InitObject = data;

            await Navigation.PushModalAsync(page, animated);
        }

        #endregion

        #region PopAsync

        /// <summary>
        /// Asynchronously removes the most recent Xamarin.Forms.Page from the navigation stack.
        /// </summary>
        /// <param name="data">The parameter which pass to the pagemodel.</param>
        /// <param name="animated">Whether to animate the pop.</param>
        /// <returns>The Xamarin.Forms.Page that had been at the top of the navigation stack.</returns>
        public async Task<Page> PopAsync(object data = null, bool animated = false)
        {
            if (LastPage == null) return null;

            _navigationAction = NavigationAction.Pop;
            _navigationTyp = NavigationTyp.Navigation;

            ReverseObject = data;

            return await Navigation.PopAsync(animated);
        }

        #endregion

        #region PopModalAsync

        /// <summary>
        /// Asynchronously dismisses the most recent modally presented Xamarin.Forms.Page.
        /// </summary>
        /// <param name="data">The parameter which pass to the pagemodel.</param>
        /// <param name="animated">Whether to animate the pop.</param>
        /// <returns>The Xamarin.Forms.Page that had been at the top of the navigation stack.</returns>
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
        /// <param name="data">The parameter which pass to the pagemodel.</param>
        /// <param name="animated">Whether to animate the pop.</param>
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
        /// <param name="page">The page to remove.</param>
        public void RemovePage(Page page)
        {
            _navigationAction = NavigationAction.Remove;
            _navigationTyp = NavigationTyp.Undefined;

            Navigation.RemovePage(page);
        }

        #endregion

        #region BackCommand

        /// <summary>
        /// Default command for back button with simple pop.
        /// </summary>
        public ICommand BackCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PopAsync();
                });
            }
        }

        #endregion

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

            popupPageModel.Setup(page);
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
        /// <param name="popupModel"></param>
        /// <param name="data">Passing data for init of the page model.</param>
        /// <param name="animated">Whether to animate the push.</param>
        public Task PushPopupAsync<TA, TB>(PopupPage page, BasePopupModel popupModel = null, object data = null, bool animated = true)
            where TA : BasePopupPageModel<TB>
            where TB : BasePopupModel
        {
            if (!(page.BindingContext is TA popupPageModel)) return null;

            if (popupModel != null)
            {
                //Create new instance to pass the popup model and reset the bindingcontext.
                popupPageModel = (TA)Activator.CreateInstance(typeof(TA), popupModel);
                page.BindingContext = popupPageModel;
            }


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

        #endregion

        #region PropertyChanged

        public event PropertyChangedEventHandler PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
