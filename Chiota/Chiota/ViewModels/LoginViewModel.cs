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
  using Tangle.Net.Cryptography.Curl;
  using Tangle.Net.Cryptography.Signing;
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

    public LoginViewModel()
    {
      this.StoreSeed = true;
      this.SubmitCommand = new Command(async () => { await this.Login(); });
      this.CopySeedCommand = new Command(this.CopySeed);
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

    public ICommand SubmitCommand { get; protected set; }

    public ICommand CopySeedCommand { get; protected set; }

    private void CopySeed()
    {
      this.DisplaySeedCopiedPrompt();
      DependencyService.Get<IClipboardService>().SendTextToClipboard(this.RandomSeed);
    }

    private async Task Login()
    {
      this.RandomSeed = this.RandomSeed?.Trim();
      if (!InputValidator.IsTrytes(this.RandomSeed))
      {
        this.DisplayInvalidLoginPrompt();
      }
      else if (!this.AlreadyClicked)
      {
        this.IsBusy = true;
        this.AlreadyClicked = true;
        var seed = new Seed(this.RandomSeed);

        // 4 addresses needed
        // 0. own user data address (encrypted, MAM or private key)
        // 1. public key address 
        // 2. request address
        // 3. approved address
        // addresses can be generated based on each other to make it faster
        var addressGenerator = await Task.Run(() => new AddressGenerator(new Kerl(), new KeyGenerator(new Kerl(), new IssSigningHelper())));
        var addresses = await Task.Run(() => addressGenerator.GetAddresses(seed, SecurityLevel.Medium, 0, 2));

        // var addresses = await this.GenerateAddressParallel(seed, 2);
        addresses.Add(Helper.GenerateAddress(addresses[0]));
        addresses.Add(Helper.GenerateAddress(addresses[1]));

        var user = new UserFactory().Create(seed, addresses);
        user = IotaHelper.GenerateKeys(user);

        // if first time only store seed after finished setup
        user.StoreSeed = this.StoreSeed;

        this.dataOnTangle = new UserDataOnTangle(user);
        user = await this.dataOnTangle.UpdateUserWithOwnDataAddress();

        if (user.Name == null)
        {
          this.IsBusy = false;
          this.AlreadyClicked = false;
          await this.Navigation.PushModalAsync(new NavigationPage(new CheckSeedStoredPage(user)));
        }
        else
        {
          user = await this.dataOnTangle.UniquePublicKey();
          if (user.StoreSeed)
          {
            new SecureStorage().StoreUser(user);
          }

          this.IsBusy = false;
          if (user.NtruChatPair != null)
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