using Chiota.ViewModels.Base;

namespace Chiota.ViewModels.BackUp
{
  using System.Windows.Input;
  using Xamarin.Forms;

  public class QrCodeViewModel : BaseViewModel
  {
    #region Attributes

    private string _seed;

    #endregion

    #region Properties

    public string Seed
    {
      get => _seed;
      set
      {
        _seed = value;
        OnPropertyChanged(nameof(Seed));
      }
    }

    #endregion

    #region Init

    public override void Init(object data = null)
    {
      base.Init(data);

      //Set a new generated seed.
      Seed = data as string;
    }

    #endregion

    #region Commands

    #region Continue

    public ICommand ContinueCommand
    {
      get
      {
        return new Command(async () => { await PopAsync(); });
      }
    }

    #endregion

    #endregion
  }
}
