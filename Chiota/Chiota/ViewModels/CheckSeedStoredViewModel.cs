using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Annotations;
  using Chiota.Models;
  using Chiota.Views;

  using Xamarin.Forms;

  public class CheckSeedStoredViewModel : BaseViewModel
  {
    public Action DisplayInvalidSeedPrompt;

    private readonly User user;

    private string seedInput;

    public CheckSeedStoredViewModel(User user)
    {
      this.user = user;
    }

    public ICommand SubmitCommand => new Command(async () => { await this.SeedCheck(); });

    [UsedImplicitly]
    public new ICommand BackCommand => new Command(async () => { await this.Back(); });

    public string SeedInput
    {
      get => this.seedInput;
      set
      {
        this.seedInput = value;
        this.OnPropertyChanged();
      }
    }

    private async Task SeedCheck()
    {
      this.SeedInput = this.SeedInput?.Trim();
      if (this.user.Seed != this.SeedInput)
      {
        this.DisplayInvalidSeedPrompt();
      }
      else if (!this.IsBusy)
      {
        this.IsBusy = true;
        await this.Navigation.PushModalAsync(new NavigationPage(new SetupPage(this.user)));
        this.IsBusy = false;
      }
    }

    private async Task Back()
    {
      if (!this.IsBusy)
      {
        this.IsBusy = true;
        await this.Navigation.PopModalAsync();
        this.IsBusy = false;
      }
    }
  }
}