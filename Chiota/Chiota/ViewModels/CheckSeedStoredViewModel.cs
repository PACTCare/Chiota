namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

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
      this.SubmitCommand = new Command(async () => { await this.SeedCheck(); });
      this.BackCommand = new Command(async () => { await this.Back(); });
    }

    public ICommand SubmitCommand { get; protected set; }

    public ICommand BackCommand { get; protected set; }

    public string SeedInput
    {
      get => this.seedInput;
      set
      {
        this.seedInput = value;
        this.RaisePropertyChanged();
      }
    }

    private async Task SeedCheck()
    {
      this.SeedInput = this.SeedInput?.Trim();
      if (this.user.Seed.ToString() != this.SeedInput)
      {
        this.DisplayInvalidSeedPrompt();
      }
      else if (!this.AlreadyClicke)
      {
        this.AlreadyClicke = true;
        await this.Navigation.PushModalAsync(new NavigationPage(new SetupPage(this.user)));
        this.AlreadyClicke = false;
      }
    }

    private async Task Back()
    {
      if (!this.AlreadyClicke)
      {
        this.AlreadyClicke = true;
        await this.Navigation.PopModalAsync();
        this.AlreadyClicke = false;
      }
    }
  }
}