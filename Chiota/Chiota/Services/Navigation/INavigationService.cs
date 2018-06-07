namespace Chiota.Services.Navigation
{
  using System.Threading.Tasks;

  using Chiota.ViewModels;

  /// <summary>
  /// The NavigationService interface.
  /// </summary>
  public interface INavigationService
  {
    /// <summary>
    /// Gets the previous page view model.
    /// </summary>
    BaseViewModel PreviousPageViewModel { get; }

    /// <summary>
    /// The navigate to async.
    /// </summary>
    /// <typeparam name="TViewModel">
    /// The ViewModel to navigate to.
    /// </typeparam>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task NavigateToAsync<TViewModel>()
      where TViewModel : BaseViewModel;

    /// <summary>
    /// The navigate to async.
    /// </summary>
    /// <param name="parameter">
    /// The parameter.
    /// </param>
    /// <typeparam name="TViewModel">
    /// The ViewModel to navigate to.
    /// </typeparam>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task NavigateToAsync<TViewModel>(object parameter)
      where TViewModel : BaseViewModel;

    /// <summary>
    /// The navigate to async.
    /// </summary>
    /// <param name="param1">
    /// The param 1.
    /// </param>
    /// <param name="param2">
    /// The param 2.
    /// </param>
    /// <typeparam name="TViewModel">
    /// The ViewModel to navigate to.
    /// </typeparam>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task NavigateToAsync<TViewModel>(object param1, object param2)
      where TViewModel : BaseViewModel;
  }
}