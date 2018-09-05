namespace Chiota.ViewModels.Help
{
  using System.Windows.Input;

  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;

  /// <summary>
  /// The seed help view model.
  /// </summary>
  public class SeedHelpViewModel : BaseViewModel
  {
    /// <summary>
    /// Gets the continue command.
    /// </summary>
    public ICommand ContinueCommand => new Command(async () => { await this.PopAsync(); });
  }
}