namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services;
  using Chiota.Views;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;

  using Xamarin.Forms;

  public class LoginViewModel : BaseViewModel
  {
    public Action DisplayInvalidLoginPrompt;

    private string randomSeed = Seed.Random().Value;

    private string username;

    private bool storeSeed;

    public LoginViewModel()
    {
      this.SubmitCommand = new Command(async () => { await this.Login(); });
    }

    public bool StoreSeed
    {
      get => this.storeSeed;
      set
      {
        this.storeSeed = value;
        this.RaisePropertyChanged();
      }
    }

    public string RandomSeed
    {
      get => this.randomSeed;
      set
      {
        this.randomSeed = value;
        this.RaisePropertyChanged();
      }
    }

    public string Username
    {
      get => this.username;
      set
      {
        this.username = value;
        this.RaisePropertyChanged();
      }
    }

    public ICommand SubmitCommand { get; protected set; }

    public INavigation Navigation { get; internal set; }

    private async Task Login()
    {
      this.randomSeed = this.randomSeed?.Trim();
      if (!IotaHelper.CorrectSeedAdressChecker(this.randomSeed))
      {
        this.DisplayInvalidLoginPrompt();
      }
      else if (!this.AlreadyClicke)
      {
        this.IsBusy = true;
        this.AlreadyClicke = true;
        var seed = new Seed(this.randomSeed);

        // 4 addresses needed: 
        // 0. own user data address (encrypted, MAM or private key)
        // 1. public key address 
        // 2. request address
        // 3. approved address
        var addresses = await Task.Factory.StartNew(() => new AddressGenerator(seed, SecurityLevel.Low).GetAddresses(0, 4));
        var user = new UserFactory().Create(seed, addresses);

        if (this.storeSeed)
        {
          new SecureStorage().StoreUser(user);
        }

        var ownDataWrappers = user.TangleMessenger.GetMessages(user.OwnDataAdress);

        if (ownDataWrappers == null || ownDataWrappers.Count == 0) 
        {
          this.IsBusy = false;
          this.AlreadyClicke = false;
          await this.Navigation.PushModalAsync(new NavigationPage(new SetupPage(user)));
        }
        else
        {
          user = IotaHelper.UpdateUserWithTangleInfos(user, ownDataWrappers);
          this.IsBusy = false;
          if (user.NtruKeyPair != null)
          {
            Application.Current.MainPage = new NavigationPage(new ContactPage(user));
            await this.Navigation.PopToRootAsync(true);
          }
          else
          {
            this.DisplayInvalidLoginPrompt();
          }
        }
      }
    }   
  }
}