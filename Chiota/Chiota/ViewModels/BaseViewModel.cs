namespace Chiota.ViewModels
{
  using System.ComponentModel;
  using System.Runtime.CompilerServices;

  public class BaseViewModel : INotifyPropertyChanged
  {
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

    public bool AlreadyClicke { get; set; }

    protected virtual void RaisePropertyChanged([CallerMemberName] string propertyName = "")
    {
      this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
  }
}
