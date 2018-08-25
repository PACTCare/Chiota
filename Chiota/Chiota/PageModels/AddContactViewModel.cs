using Chiota.PageModels.Classes;
using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
  using System.Diagnostics;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Extensions;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Models;
  using Chiota.Persistence;
  using Chiota.Popups.PopupModels;
  using Chiota.Popups.PopupPageModels;
  using Chiota.Popups.PopupPages;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Iota;
  using Chiota.Services.Iota.Repository;
  using Chiota.Services.UserServices;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository.Factory;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  using ZXing.Net.Mobile.Forms;

  public class AddContactViewModel : BasePageModel
  using TangleMessenger = Chiota.Messenger.Service.TangleMessenger;
  {
    private string receiverAdress;

    private string qrSource;

    public AddContactViewModel()
    {
      this.QrSource = UserService.CurrentUser.PublicKeyAddress;

      // TODO: this has to be completely done via DI 
      this.AddContactInteractor = new AddContactInteractor(
        DependencyResolver.Resolve<AbstractSqlLiteDb>(),
        new TangleMessenger(DependencyResolver.Resolve<IRepositoryFactory>().Create()));
    }

    public AddContactInteractor AddContactInteractor { get; }

    public string QrSource
    {
      get => this.qrSource;
      set
      {
        this.qrSource = value;
        this.OnPropertyChanged();
      }
    }

    public string ReceiverAdress
    {
      get => this.receiverAdress ?? string.Empty;
      set
      {
        this.receiverAdress = value;
        this.OnPropertyChanged();
      }
    }

    public string UserAddress => UserService.CurrentUser.PublicKeyAddress;

    public ICommand SubmitCommand => new Command(async () => { await this.AddContact(); });

    public ICommand ScanCommand => new Command(async () => { await this.ScanBarcode(); });

    public void AddAdressToClipboard()
    {
      DependencyResolver.Resolve<IClipboardService>().SendTextToClipboard(UserService.CurrentUser.PublicKeyAddress);
    }

    private async Task SaveParallel(Contact loadedContact)
    {
      var request = new AddContactRequest
      {
        Name = UserService.CurrentUser.Name,
        ImageHash = UserService.CurrentUser.ImageHash,
        RequestAddress = new Address(UserService.CurrentUser.RequestAddress),
        PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
        ContactAddress = new Address(loadedContact.ContactAddress),
        ContactNtruKey = loadedContact.NtruKey
      };

      var response = await this.AddContactInteractor.ExecuteAsync(request);

      // TODO: This has to go in a presenter!
      if (response.Code != ResponseCode.Success)
      {
        Debug.WriteLine(response.Code.ToString("G"));
        await this.DisplayAlert("Error", "The contact could not be added. Please try again later.");
      }
      else
      {
        await this.DisplayAlert("Successful Request", "Your new contact needs to accept the request before you can start chatting!.");
      }
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
            await this.DisplayAlert("Error", "The provided address is invalid.");
          }
          else if (contacts[0]?.NtruKey != null && contacts[0].ContactAddress != null)
          {
            await this.SaveParallel(contacts[0]);
          }
        }
        else
        {
          await this.DisplayAlert("Error", "The provided address is invalid.");
        }

        this.IsBusy = false;
      }
    }

    private async Task DisplayAlert(string title, string message)
    {
      await this.Navigation.DisplayPopupAsync<AlertPopupPageModel, AlertPopupModel>(
        new AlertPopupPage(),
        new AlertPopupModel { Title = title, Message = message });
    }
  }
}
