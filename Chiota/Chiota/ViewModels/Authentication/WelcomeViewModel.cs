namespace Chiota.ViewModels.Authentication
{
  using System.Windows.Input;

  using Chiota.Pages.Authentication;
  using Chiota.Pages.Help;
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;

  /// <summary>
  /// The welcome view model.
  /// </summary>
  public class WelcomeViewModel : BaseViewModel
  {
    public ICommand NewSeedCommand => new Command(async () => { await this.PushAsync(new NewSeedPage()); });

    public ICommand SeedHelpCommand => new Command(async () => { await this.PushAsync(new SeedHelpPage()); });

    public ICommand SetSeedCommand => new Command(async () => { await this.PushAsync(new SetSeedPage()); });
  }
}