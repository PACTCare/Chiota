namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

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

    public string UserAddress => this.user.PublicKeyAddress;

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

      if (!this.AlreadyClicked)
      {
        this.IsBusy = true;
        this.AlreadyClicked = true;

        if (InputValidator.IsAddress(this.ReceiverAdress) && this.ReceiverAdress != this.user.PublicKeyAddress)
        {
          // get information from receiver adress 
          var trytes = await this.user.TangleMessenger.GetMessagesAsync(this.ReceiverAdress, 3);
          var contacts = IotaHelper.GetPublicKeysAndContactAddresses(trytes);

          if (contacts == null || contacts.Count == 0 || contacts.Count > 1)
          {
            this.DisplayInvalidAdressPrompt();
          }
          else if (contacts[0]?.PublicNtruKey != null && contacts[0].ContactAddress != null)
          {
            await this.SendParallel(contacts[0].ContactAddress);

            this.SuccessfulRequestPrompt();
          }
        }
        else
        {
          this.DisplayInvalidAdressPrompt();
        }

        this.IsBusy = false;
        this.AlreadyClicked = false;
      }
    }

    private Task SendParallel(string contactAddress)
    {
      var requestContact = new Contact()
      {
        // faster than generating adresses
        ChatAddress = Seed.Random().ToString(),
        Name = this.user.Name,
        ImageUrl = this.user.ImageUrl,
        ContactAddress = this.user.RequestAddress,
        Request = true,
        Rejected = false,
        PublicNtruKey = null,
        PublicKeyAddress = this.user.PublicKeyAddress
      };

      var encryptedAccept = new NtruKex().Encrypt(this.user.NtruContactPair.PublicKey, requestContact.ChatAddress + ChiotaConstants.Accepted);
      var tryteString = new TryteString(encryptedAccept.EncodeBytesAsString() + ChiotaConstants.End);

      // automaticly add to own accept list, so contact is shown as soon as it as accepted by the other user
      var firstTransaction = this.user.TangleMessenger.SendMessageAsync(tryteString, this.user.ApprovedAddress);

      // encrypt contact request? too much infos needed here for one message needs to get request address plus chatadress 
      var secondTransaction = this.user.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(requestContact), contactAddress);

      return Task.WhenAll(firstTransaction, secondTransaction);
    }
  }
}
