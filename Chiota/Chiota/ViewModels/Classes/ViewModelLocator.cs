using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Text;
using TinyIoC;
using Xamarin.Forms;

namespace Chiota.ViewModels.Classes
{
    public static class ViewModelLocator
    {
        #region Attributes

        private static TinyIoCContainer _container;

        #endregion

        #region Properties

        public static readonly BindableProperty AutoWireViewModelProperty =
            BindableProperty.CreateAttached("AutoWireViewModel", typeof(bool), typeof(ViewModelLocator), default(bool), propertyChanged: OnAutoWireViewModelChanged);

        #endregion

        #region Constructors

        static ViewModelLocator()
        {
            _container = new TinyIoCContainer();
        }

        #endregion

        #region Methods

        #region GetAutoWireViewModel

        public static bool GetAutoWireViewModel(BindableObject bindable)
        {
            return (bool)bindable.GetValue(ViewModelLocator.AutoWireViewModelProperty);
        }

        #endregion

        #region SetAutoWireViewModel

        public static void SetAutoWireViewModel(BindableObject bindable, bool value)
        {
            bindable.SetValue(ViewModelLocator.AutoWireViewModelProperty, value);
        }

        #endregion

        #region RegisterSingleton

        public static void RegisterSingleton<TInterface, T>() where TInterface : class where T : class, TInterface
        {
            _container.Register<TInterface, T>().AsSingleton();
        }

        #endregion

        #region Resolve

        public static T Resolve<T>() where T : class
        {
            return _container.Resolve<T>();
        }

        #endregion

        #endregion

        #region Events

        #region OnAutoWireViewModelChanged

        private static void OnAutoWireViewModelChanged(BindableObject bindable, object oldValue, object newValue)
        {
            var view = bindable as Element;
            if (view == null)
            {
                return;
            }

            var viewType = view.GetType();
            //var viewName = viewType.FullName.Replace(".Views.", ".ViewModels.");
            var viewAssemblyName = viewType.GetTypeInfo().Assembly.FullName;
            var viewModelName = string.Format(CultureInfo.InvariantCulture, "{0}Model, {1}", viewType.FullName, viewAssemblyName); //viewName instead of viewType.FullName

            var viewModelType = Type.GetType(viewModelName);
            if (viewModelType == null)
            {
                return;
            }
            var viewModel = _container.Resolve(viewModelType);
            view.BindingContext = viewModel;
        }

        #endregion

        #endregion
    }
}
