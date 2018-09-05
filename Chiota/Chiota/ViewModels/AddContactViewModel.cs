using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Extensions;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Popups.PopupModels;
  using Chiota.Popups.PopupPageModels;
  using Chiota.Popups.PopupPages;
  using Chiota.Presenters;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;

  using Rg.Plugins.Popup.Extensions;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  using ZXing.Net.Mobile.Forms;

  public class AddContactViewModel : BaseViewModel
  {
    private string receiverAdress;

    private string qrSource;

    public AddContactViewModel(IUsecaseInteractor<AddContactRequest, AddContactResponse> addContactInteractor)
    {
      this.QrSource = UserService.CurrentUser.PublicKeyAddress;
      this.AddContactInteractor = addContactInteractor;
    }

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

    private IUsecaseInteractor<AddContactRequest, AddContactResponse> AddContactInteractor { get; }

    public void AddAdressToClipboard()
    {
      DependencyResolver.Resolve<IClipboardService>().SendTextToClipboard(UserService.CurrentUser.PublicKeyAddress);
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

      if (InputValidator.IsAddress(this.ReceiverAdress) && this.ReceiverAdress != UserService.CurrentUser.PublicKeyAddress)
      {
        await this.DisplayLoadingSpinnerAsync("Adding Contact");

        var response = await this.AddContactInteractor.ExecuteAsync(
                         new AddContactRequest
                           {
                             Name = UserService.CurrentUser.Name,
                             ImageHash = UserService.CurrentUser.ImageHash,
                             RequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                             PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                             ContactAddress = new Address(this.ReceiverAdress)
                           });

        await this.Navigation.PopPopupAsync();
        await AddContactPresenter.Present(this, response);
      }
      else
      {
        await this.DisplayAlertAsync("Error", "The provided address is invalid.");
      }
    }
  }
}
