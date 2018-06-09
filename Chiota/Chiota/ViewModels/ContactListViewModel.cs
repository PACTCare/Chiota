namespace Chiota.ViewModels
{
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services;
  using Chiota.Services.UserServices;

  using Tangle.Net.Entity;

  using Xamarin.Forms;

  public class ContactListViewModel : Contact
  {
    private readonly ViewCellObject viewCellObject;

    private string poWText;

    private bool isClicked;

    public ContactListViewModel(ViewCellObject viewCellObject)
    {
      this.PoWText = string.Empty;
      this.viewCellObject = viewCellObject;
    }

    public ICommand AcceptCommand => new Command(async () => { await this.OnAccept(); });

    public ICommand DeclineCommand => new Command(async () => { await this.OnDecline(); });

    public string PoWText
    {
      get => this.poWText;
      set
      {
        this.poWText = value;
        this.RaisePropertyChanged();
      }
    }

    private async Task OnDecline()
    {
      if (!this.isClicked)
      {
        this.isClicked = true;
        this.PoWText = " Proof-of-work in progress!";

        var encryptedDecline = new NtruKex().Encrypt(UserService.CurrentUser.NtruContactPair.PublicKey, this.ChatAddress + ChiotaConstants.Rejected);
        var tryteString = new TryteString(encryptedDecline.EncodeBytesAsString() + ChiotaConstants.End);

        await UserService.CurrentUser.TangleMessenger.SendMessageAsync(tryteString, UserService.CurrentUser.ApprovedAddress);
        this.viewCellObject.RefreshContacts = true;
        this.isClicked = false;
      }
    }

    private async Task OnAccept()
    {
      if (!this.isClicked)
      {
        this.isClicked = true;
        this.PoWText = " Proof-of-work in progress!";

        await this.SendParallelAcceptAsync();

        this.viewCellObject.RefreshContacts = true;
        this.isClicked = false;
      }
    }

    // parallelize = only await for second PoW, when remote PoW 
    private Task SendParallelAcceptAsync()
    {
      var encryptedAccept = new NtruKex().Encrypt(UserService.CurrentUser.NtruContactPair.PublicKey, this.ChatAddress + ChiotaConstants.Accepted);
      var tryteString = new TryteString(encryptedAccept.EncodeBytesAsString() + ChiotaConstants.End);

      // store as approved on own adress
      var firstTransaction = UserService.CurrentUser.TangleMessenger.SendMessageAsync(tryteString, UserService.CurrentUser.ApprovedAddress);

      var contact = new Contact
                      {
                        Name = UserService.CurrentUser.Name,
                        ImageUrl = UserService.CurrentUser.ImageUrl,
                        ChatAddress = this.ChatAddress,
                        ContactAddress = UserService.CurrentUser.ApprovedAddress,
                        PublicKeyAddress = UserService.CurrentUser.PublicKeyAddress,
                        Rejected = false,
                        Request = false
                      };

      // send data to request address, other user needs to automaticly add it to his own approved contact address
      var secondTransaction = UserService.CurrentUser.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(contact), this.ContactAddress);
      return Task.WhenAll(firstTransaction, secondTransaction);
    }
  }
}
