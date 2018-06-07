namespace Chiota.ViewModels
{
  using System.ComponentModel;
  using System.Runtime.CompilerServices;

  using Chiota.Services.Navigation;

  using Xamarin.Forms;

  public class BaseViewModel : INotifyPropertyChanged
  {
    private static INavigationService navigationService;

    public INavigationService NavigationService => navigationService ?? (navigationService = new NavigationService());

    private bool isBusy;

    public event PropertyChangedEventHandler PropertyChanged;

    public bool IsBusy
    {
      get => this.isBusy;
      set
      {
        this.isBusy = value;
        this.RaisePropertyChanged();
      }
    }

    public INavigation Navigation { get; internal set; }

    public bool AlreadyClicked { get; set; }

    protected virtual void RaisePropertyChanged([CallerMemberName] string propertyName = "")
    {
      this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
  }
}
