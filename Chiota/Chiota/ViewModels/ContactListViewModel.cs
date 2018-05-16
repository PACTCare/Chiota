namespace Chiota.ViewModels
{
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  public class ContactListViewModel : Contact
  {
    private readonly User user;

    private readonly ViewCellObject viewCellObject;

    private string poWText;

    private bool isClicked;

    public ContactListViewModel(User user, ViewCellObject viewCellObject)
    {
      this.user = user;
      this.PoWText = string.Empty;
      this.viewCellObject = viewCellObject;
      this.AcceptCommand = new Command(async () => { await this.OnAccept(); });
      this.DeclineCommand = new Command(async () => { await this.OnDecline(); });
    }

    public ICommand AcceptCommand { get; protected set; }

    public ICommand DeclineCommand { get; protected set; }

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

        var encryptedDecline = new NtruKex().Encrypt(this.user.NtruContactPair.PublicKey, this.ChatAddress + ChiotaConstants.Rejected);
        var tryteString = new TryteString(encryptedDecline.ToTrytes() + ChiotaConstants.End);

        await this.user.TangleMessenger.SendMessageAsync(tryteString, this.user.ApprovedAddress);
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
      var encryptedAccept = new NtruKex().Encrypt(this.user.NtruContactPair.PublicKey, this.ChatAddress + ChiotaConstants.Accepted);
      var tryteString = new TryteString(encryptedAccept.ToTrytes() + ChiotaConstants.End);

      // store as approved on own adress
      var firstTransaction = this.user.TangleMessenger.SendMessageAsync(tryteString, this.user.ApprovedAddress);

      var contact = new Contact
                      {
                        Name = this.user.Name,
                        ImageUrl = this.user.ImageUrl,
                        ChatAddress = this.ChatAddress,
                        ContactAddress = this.user.ApprovedAddress,
                        PublicKeyAddress = this.user.PublicKeyAddress,
                        Rejected = false,
                        Request = false
                      };

      // send data to request address, other user needs to automaticly add it to his own approved contact address
      var secondTransaction = this.user.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(contact), this.ContactAddress);
      return Task.WhenAll(firstTransaction, secondTransaction);
    }
  }
}
