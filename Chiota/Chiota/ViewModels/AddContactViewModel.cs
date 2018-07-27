namespace Chiota.ViewModels
{
  using System;
  using System.Text;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Models;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Iota;
  using Chiota.Services.UserServices;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  using ZXing.Net.Mobile.Forms;

  public class AddContactViewModel : BaseViewModel
  {
    private string receiverAdress;

    private string qrSource;

    public AddContactViewModel()
    {
      this.QrSource = UserService.CurrentUser.PublicKeyAddress;
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
      get => this.receiverAdress ?? string.Empty;
      set
      {
        this.receiverAdress = value;
        this.RaisePropertyChanged();
      }
    }

    public string UserAddress => UserService.CurrentUser.PublicKeyAddress;

    public ICommand SubmitCommand => new Command(async () => { await this.AddContact(); });

    public ICommand ScanCommand => new Command(async () => { await this.ScanBarcode(); });

    public void AddAdressToClipboard()
    {
      DependencyResolver.Resolve<IClipboardService>().SendTextToClipboard(UserService.CurrentUser.PublicKeyAddress);
    }

    private static async Task SaveParallel(Contact loadedContact)
    {
      var requestContact = new Contact
                             {
                               // faster than generating adresses
                               ChatAddress = Seed.Random().ToString(),
                               ChatKeyAddress = Seed.Random().ToString(),
                               Name = UserService.CurrentUser.Name,
                               ImageHash = UserService.CurrentUser.ImageHash,
                               ContactAddress = UserService.CurrentUser.RequestAddress,
                               Request = true,
                               Rejected = false,
                               NtruKey = null,
                               PublicKeyAddress = UserService.CurrentUser.PublicKeyAddress
                             };

      var saveSqlContact = new SqLiteHelper().SaveContact(requestContact.ChatAddress, true, UserService.CurrentUser.PublicKeyAddress);

      // encrypt contact request? too much infos needed here for one message needs to get request address plus chatadress 
      var chatInformationToTangle = UserService.CurrentUser.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(requestContact), loadedContact.ContactAddress);

      var encryptedChatPasSalt = new NtruKex(true).Encrypt(loadedContact.NtruKey, Encoding.UTF8.GetBytes(Seed.Random() + Seed.Random().ToString().Substring(0, 20)));
      var encryptedChatKeyToTangle = UserService.CurrentUser.TangleMessenger.SendMessageAsync(new TryteString(encryptedChatPasSalt.EncodeBytesAsString() + ChiotaConstants.End), requestContact.ChatKeyAddress);

      await Task.WhenAll(saveSqlContact, chatInformationToTangle, encryptedChatKeyToTangle);
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
      this.ReceiverAdress = this.ReceiverAdress.Trim();

      if (!this.IsBusy)
      {
        this.IsBusy = true;

        if (InputValidator.IsAddress(this.ReceiverAdress) && this.ReceiverAdress != UserService.CurrentUser.PublicKeyAddress)
        {
          // get information from receiver adress 
          var contacts = await IotaHelper.GetPublicKeysAndContactAddresses(UserService.CurrentUser.TangleMessenger, this.ReceiverAdress);

          if (contacts == null || contacts.Count == 0 || contacts.Count > 1)
          {
            this.DisplayInvalidAdressPrompt();
          }
          else if (contacts[0]?.NtruKey != null && contacts[0].ContactAddress != null)
          {
            await SaveParallel(contacts[0]);

            this.SuccessfulRequestPrompt();
          }
        }
        else
        {
          this.DisplayInvalidAdressPrompt();
        }

        this.IsBusy = false;
      }
    }
  }
}
