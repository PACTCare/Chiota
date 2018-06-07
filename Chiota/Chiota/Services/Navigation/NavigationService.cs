namespace Chiota.Services.Navigation
{
  using System;
  using System.Globalization;
  using System.Reflection;
  using System.Threading.Tasks;

  using Chiota.ViewModels;

  using Xamarin.Forms;

  /// <inheritdoc />
  public class NavigationService : INavigationService
  {
    /// <inheritdoc />
    public BaseViewModel PreviousPageViewModel
    {
      get
      {
        var mainPage = Application.Current.MainPage as NavigationPage;
        var viewModel = mainPage.Navigation.NavigationStack[mainPage.Navigation.NavigationStack.Count - 2].BindingContext;
        return viewModel as BaseViewModel;
      }
    }

    /// <inheritdoc />
    public Task NavigateToAsync<TViewModel>()
      where TViewModel : BaseViewModel
    {
      return this.InternalNavigateToAsync(typeof(TViewModel), null);
    }

    /// <inheritdoc />
    public Task NavigateToAsync<TViewModel>(object parameter)
      where TViewModel : BaseViewModel
    {
      return this.InternalNavigateToAsync(typeof(TViewModel), parameter);
    }

    /// <inheritdoc />
    public Task NavigateToAsync<TViewModel>(object param1, object param2)
      where TViewModel : BaseViewModel
    {
      return this.InternalNavigateToAsync(typeof(TViewModel), param1, param2);
    }
    private static Type GetPageTypeForViewModel(Type viewModelType)
    {
      var viewName = viewModelType.FullName.Replace("ViewModel", "Page").Replace("Pages", "Views");
      var viewModelAssemblyName = viewModelType.GetTypeInfo().Assembly.FullName;
      var viewAssemblyName = string.Format(CultureInfo.InvariantCulture, "{0}, {1}", viewName, viewModelAssemblyName);
      var viewType = Type.GetType(viewAssemblyName);
      return viewType;
    }

    private Page CreatePage(Type viewModelType, object param1, object param2)
    {
      var pageType = GetPageTypeForViewModel(viewModelType);
      if (pageType == null)
      {
        throw new Exception($"Cannot locate page type for {viewModelType}");
      }

      if (param1 != null && param2 != null)
      {
        return Activator.CreateInstance(pageType, param1, param2) as Page;
      }

      if (param1 != null)
      {
        return Activator.CreateInstance(pageType, param1) as Page;
      }

      return Activator.CreateInstance(pageType) as Page;
    }

    /// <summary>
    /// The internal navigate to async.
    /// </summary>
    /// <param name="viewModelType">
    /// The view model type.
    /// </param>
    /// <param name="param1">
    /// The param 1.
    /// </param>
    /// <param name="param2">
    /// The param 2.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task InternalNavigateToAsync(Type viewModelType, object param1, object param2 = null)
    {
      var page = this.CreatePage(viewModelType, param1, param2);
      Application.Current.MainPage = new NavigationPage(page);
    }
  }
}