namespace Chiota.ViewModels
{
  using System;
  using System.Collections.Generic;
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
        var addresses = await this.GenerateAddressParallel(seed, 4);
        var user = new UserFactory().Create(seed, addresses);
        user.NtruChatPair = new NtruKex().CreateAsymmetricKeyPair(user.Seed.ToString(), user.OwnDataAdress);
        user.NtruContactPair = new NtruKex().CreateAsymmetricKeyPair(user.Seed.ToString(), user.ApprovedAddress);

        // if first time only store seed after finished setup
        user.StoreSeed = this.StoreSeed;

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

    private async Task<List<Address>> GenerateAddressParallel(Seed seed, int numberOfAddresses)
    {
      var addresses = new List<Address>();
      var taskList = new List<Task<List<Address>>>();
      for (var i = 0; i < numberOfAddresses; i++)
      {
        var addressGenerator = new AddressGenerator(new Kerl(), new KeyGenerator(new Kerl(), new IssSigningHelper()));
        var localI = i;
        taskList.Add(Task.Run(() => addressGenerator.GetAddresses(seed, SecurityLevel.Medium, localI, 1)));
      }

      var array = await Task.WhenAll(taskList.ToArray());
      foreach (var address in array)
      {
        addresses.AddRange(address);
      }

      return addresses;
    }
  }
}