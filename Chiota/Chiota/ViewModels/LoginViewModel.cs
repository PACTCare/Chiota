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

  using ContactPage = Views.ContactPage;

  public class LoginViewModel : BaseViewModel
  {
    public Action DisplayInvalidLoginPrompt;

    private string randomSeed = Seed.Random().Value;

    private string username;

    private bool storeSeed;

    private UserDataOnTangle dataOnTangle;

    public LoginViewModel()
    {
      this.StoreSeed = true;
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

    private async Task Login()
    {
      this.RandomSeed = this.RandomSeed?.Trim();
      if (!IotaHelper.CorrectSeedAdressChecker(this.RandomSeed))
      {
        this.DisplayInvalidLoginPrompt();
      }
      else if (!this.AlreadyClicke)
      {
        this.IsBusy = true;
        this.AlreadyClicke = true;
        var seed = new Seed(this.RandomSeed);

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

        this.dataOnTangle = new UserDataOnTangle(user);
        user = await this.dataOnTangle.UpdateUserWithOwnDataAddress();

        if (user.Name == null) 
        {
          this.IsBusy = false;
          this.AlreadyClicke = false;
          await this.Navigation.PushModalAsync(new NavigationPage(new CheckSeedStoredPage(user)));
        }
        else
        {
          user = await this.dataOnTangle.UpdateUserWithPublicKeyAddress();
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