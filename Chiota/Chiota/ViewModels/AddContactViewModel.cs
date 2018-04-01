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

    private string qrSource;

    public AddContactViewModel(User user)
    {
      this.user = user;
      this.QrSource = this.user.PublicKeyAddress;
      this.SubmitCommand = new Command(async () => { await this.AddContact(); });
    }

    public Action DisplayInvalidAdressPrompt { get; set; }

    public string QrSource
    {
      get => this.qrSource;
      set
      {
        this.qrSource = value;
        this.RaisePropertyChanged();
      }
    }

    public string UserAdress => this.user.PublicKeyAddress;

    public string ReceiverAdress { get; set; }

    public ICommand SubmitCommand { get; set; }

    public void AddAdressToClipboard()
    {
      DependencyService.Get<IClipboardService>().SendTextToClipboard(this.user.PublicKeyAddress);
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
        try
        {
          // get information from receiver adress 
          var trytes = await this.user.TangleMessenger.GetMessagesAsync(this.ReceiverAdress, 3);
          var contact = IotaHelper.FilterRequestInfos(trytes);

          if (contact?.PublicNtruKey != null && contact.ContactAdress != null)
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
            await this.user.TangleMessenger.SendJsonMessageAsync(new SentDataWrapper<Contact> { Data = requestContact, Sender = this.user.Name }, contact.ContactAdress);
          }
        }
        catch 
        {
          this.DisplayInvalidAdressPrompt();
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
