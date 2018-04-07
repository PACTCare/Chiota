namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services;

  using Tangle.Net.Entity;

  using Xamarin.Forms;

  using ZXing.Net.Mobile.Forms;

  public class AddContactViewModel : BaseViewModel
  {
    private readonly User user;

    private string receiverAdress;

    private string qrSource;

    public AddContactViewModel(User user)
    {
      this.user = user;
      this.QrSource = this.user.PublicKeyAddress;
      this.SubmitCommand = new Command(async () => { await this.AddContact(); });
      this.ScanCommand = new Command(async () => { await this.ScanBarcode(); });
    }

    public Action DisplayInvalidAdressPrompt { get; set; }

    public Action SuccessfulRequestPrompt { get; set; }

    public string QrSource
    {
      get => this.qrSource;
      set
      {
        this.qrSource = value;
        this.RaisePropertyChanged();
      }
    }

    public string ReceiverAdress
    {
      get => this.receiverAdress;
      set
      {
        this.receiverAdress = value;
        this.RaisePropertyChanged();
      }
    }

    public string UserAdress => this.user.PublicKeyAddress;

    public ICommand SubmitCommand { get; set; }

    public ICommand ScanCommand { get; set; }

    public void AddAdressToClipboard()
    {
      DependencyService.Get<IClipboardService>().SendTextToClipboard(this.user.PublicKeyAddress);
    }

    private async Task ScanBarcode()
    {
      var scanPage = new ZXingScannerPage();
      scanPage.OnScanResult += (result) =>
      {
        scanPage.IsScanning = false;

        Device.BeginInvokeOnMainThread(() =>
        {
          this.Navigation.PopAsync();
          this.ReceiverAdress = result.Text;
        });
      };

      await this.Navigation.PushAsync(scanPage);
    }

    private async Task AddContact()
    {
      this.ReceiverAdress = this.ReceiverAdress?.Trim();

      if (!this.AlreadyClicke &&
          IotaHelper.CorrectSeedAdressChecker(this.ReceiverAdress) &&
          this.ReceiverAdress?.Length == 81 &&
          this.ReceiverAdress != this.user.PublicKeyAddress)
      {
        this.IsBusy = true;
        this.AlreadyClicke = true;

        // get information from receiver adress 
        var trytes = await this.user.TangleMessenger.GetMessagesAsync(this.ReceiverAdress, 3);
        var contacts = IotaHelper.GetPublicKeysAndContactAddresses(trytes);

        if (contacts == null || contacts.Count > 1)
        {
          this.DisplayInvalidAdressPrompt();
        }
        else if (contacts[0]?.PublicNtruKey != null && contacts[0].ContactAdress != null)
        {
          // faster than generating adresses
          var requestContact = new Contact()
          {
            ChatAdress = Seed.Random().ToString(),
            Name = this.user.Name,
            ImageUrl = this.user.ImageUrl,
            ContactAdress = this.user.ApprovedAddress,
            Request = true,
            Rejected = false,
            PublicNtruKey = null,
            PublicKeyAdress = this.user.PublicKeyAddress
          };

          // encrypt contact request? too much infos needed here for one message needs to get request adress plus chatadress 
          await this.user.TangleMessenger.SendJsonMessageAsync(new SentDataWrapper<Contact> { Data = requestContact, Sender = this.user.Name }, contacts[0].ContactAdress);
          this.SuccessfulRequestPrompt();
        }
      }
      else
      {
        this.DisplayInvalidAdressPrompt();
      }

      this.IsBusy = false;
      this.AlreadyClicke = false;
    }
  }
}
