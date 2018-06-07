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
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  using ContactPage = Views.ContactPage;

  public class LoginViewModel : BaseViewModel
  {
    public Action DisplayInvalidLoginPrompt;

    public Action DisplaySeedCopiedPrompt;

    private string randomSeed = Seed.Random().Value;

    private bool storeSeed;

    private UserDataOnTangle dataOnTangle;

    private User user;

    public LoginViewModel()
    {
      this.StoreSeed = true;
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
      get => this.randomSeed ?? string.Empty;
      set
      {
        this.randomSeed = value;
        this.RaisePropertyChanged();
      }
    }

    public ICommand SubmitCommand => new Command(async () => { await this.Login(); });

    public ICommand CopySeedCommand => new Command(this.CopySeed);

    private void CopySeed()
    {
      this.DisplaySeedCopiedPrompt();
      DependencyService.Get<IClipboardService>().SendTextToClipboard(this.RandomSeed);
    }

    private async Task Login()
    {
      this.RandomSeed = this.RandomSeed.Trim();
      if (!InputValidator.IsTrytes(this.RandomSeed))
      {
        this.DisplayInvalidLoginPrompt();
      }
      else if (!this.AlreadyClicked)
      {
        this.IsBusy = true;
        this.AlreadyClicked = true;

        // Don't generate addresses again, in case user uses the back button to copy the seed and doesn't change it.
        if (this.user == null || this.RandomSeed != this.user?.Seed.Value)
        {
          var seed = new Seed(this.RandomSeed);

        // 4 addresses needed
        // 0. own user data address (encrypted, MAM or private key)
        // 1. public key address 
        // 2. request address
        // 3. approved address
        // addresses can be generated based on each other to make it faster
        var addresses = await Task.Run(() => new AddressGenerator().GetAddresses(seed, SecurityLevel.Medium, 0, 2));

          // var addresses = await this.GenerateAddressParallel(seed, 2);
          addresses.Add(Helper.GenerateAddress(addresses[0]));
          addresses.Add(Helper.GenerateAddress(addresses[1]));

          this.user = new UserFactory().Create(seed, addresses);
          this.user = IotaHelper.GenerateKeys(this.user);
        }

        // if first time only store seed after finished setup
        this.user.StoreSeed = this.StoreSeed;

        this.dataOnTangle = new UserDataOnTangle(this.user);
        this.user = await this.dataOnTangle.UpdateUserWithOwnDataAddress();

        if (this.user.Name == null)
        {
          this.IsBusy = false;
          this.AlreadyClicked = false;
          await this.Navigation.PushModalAsync(new NavigationPage(new CheckSeedStoredPage(this.user)));
        }
        else
        {
          this.user = await this.dataOnTangle.UniquePublicKey();
          if (this.user.StoreSeed)
          {
            new SecureStorage().StoreUser(this.user);
          }

          this.IsBusy = false;
          if (this.user.NtruChatPair != null)
          {
            await this.NavigationService.NavigateToAsync<ContactViewModel>(this.user);
            //Application.Current.MainPage = new NavigationPage(new ContactPage(this.user));
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