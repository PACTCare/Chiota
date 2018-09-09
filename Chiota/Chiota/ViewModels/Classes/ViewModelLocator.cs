namespace Chiota.ViewModels.Classes
{
  using System;
  using System.Globalization;
  using System.Reflection;

  using Autofac;

  using Chiota.Services.DependencyInjection;

  using Xamarin.Forms;

  public static class ViewModelLocator
  {
    public static readonly BindableProperty AutoWireViewModelProperty = BindableProperty.CreateAttached(
      "AutoWireViewModel",
      typeof(bool),
      typeof(ViewModelLocator),
      default(bool),
      propertyChanged: OnAutoWireViewModelChanged);

    public static bool GetAutoWireViewModel(BindableObject bindable)
    {
      return (bool)bindable.GetValue(AutoWireViewModelProperty);
    }

    public static T Resolve<T>()
      where T : class
    {
      return DependencyResolver.Resolve<T>();
    }

    public static void SetAutoWireViewModel(BindableObject bindable, bool value)
    {
      bindable.SetValue(AutoWireViewModelProperty, value);
    }

    private static void OnAutoWireViewModelChanged(BindableObject bindable, object oldValue, object newValue)
    {
      if (!(bindable is Element view))
      {
        return;
      }

      var viewType = view.GetType();

      var viewName = viewType.FullName.Replace(".Pages.", ".ViewModels.");
      var viewAssemblyName = viewType.GetTypeInfo().Assembly.FullName;
      var viewModelName = string.Format(CultureInfo.InvariantCulture, "{0}Model, {1}", viewName, viewAssemblyName).Replace("Page", "View");

      var viewModelType = Type.GetType(viewModelName);
      if (viewModelType == null)
      {
        return;
      }

      var viewModel = DependencyResolver.Resolve(viewModelType);
      view.BindingContext = viewModel;
    }
  }
}