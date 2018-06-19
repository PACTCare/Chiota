namespace Chiota.ViewModels
{
  using System.Text;
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
    private readonly User user;

    private readonly ViewCellObject viewCellObject;

    private string poWText;

    private bool isClicked;

    public ContactListViewModel(User user, ViewCellObject viewCellObject)
    {
      this.user = user;
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

        var encryptedDecline = new NtruKex(true).Encrypt(this.user.NtruKeyPair.PublicKey, Encoding.UTF8.GetBytes(this.ChatAddress + ChiotaConstants.Rejected));
        var tryteString = new TryteString(encryptedDecline.EncodeBytesAsString() + ChiotaConstants.End);

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

    private async Task SendParallelAcceptAsync()
    {
      var encryptedAccept = new NtruKex(true).Encrypt(this.user.NtruKeyPair.PublicKey, Encoding.UTF8.GetBytes(this.ChatAddress + ChiotaConstants.Accepted));
      var tryteString = new TryteString(encryptedAccept.EncodeBytesAsString() + ChiotaConstants.End);

      var encryptedChatKeyToTangle = await this.GenerateChatKeyToTangle();

      // Todo: doesn't need to be on the tangle!!!!!!!!
      // store as approved on own adress
      var firstTransaction = this.user.TangleMessenger.SendMessageAsync(tryteString, this.user.ApprovedAddress);

      var contact = new Contact
      {
        Name = this.user.Name,
        ImageUrl = this.user.ImageUrl,
        ChatAddress = this.ChatAddress,
        ChatKeyAddress = this.ChatKeyAddress,
        ContactAddress = this.user.ApprovedAddress,
        PublicKeyAddress = this.user.PublicKeyAddress,
        Rejected = false,
        Request = false,
        NtruKey = null
      };

      var chatInformationToTangle = UserService.CurrentUser.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(contact), this.ContactAddress);
      await Task.WhenAll(firstTransaction, chatInformationToTangle, encryptedChatKeyToTangle);
    }

    private async Task<Task<bool>> GenerateChatKeyToTangle()
    {
      var contacts = await IotaHelper.GetPublicKeysAndContactAddresses(UserService.CurrentUser.TangleMessenger, this.PublicKeyAddress);
      var pasSalt = await IotaHelper.GetChatPasSalt(this.user, this.ChatKeyAddress);
      var encryptedChatPasSalt = new NtruKex(true).Encrypt(contacts[0].NtruKey, Encoding.UTF8.GetBytes(pasSalt));
      return UserService.CurrentUser.TangleMessenger.SendMessageAsync(new TryteString(encryptedChatPasSalt.EncodeBytesAsString() + ChiotaConstants.End), this.ChatKeyAddress);
    }
  }
}
