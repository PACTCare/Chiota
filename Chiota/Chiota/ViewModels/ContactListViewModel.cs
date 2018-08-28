namespace Chiota.ViewModels
{
  using System.ComponentModel;
  using System.Runtime.CompilerServices;
  using System.Text;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Messenger.Entity;
  using Chiota.Models;
  using Chiota.Persistence;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Iota;
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
      this.ContactRepository = DependencyResolver.Resolve<AbstractSqlLiteDb>();
    }

    public event PropertyChangedEventHandler PropertyChanged;

    public AbstractSqlLiteDb ContactRepository { get; }

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
        await this.ContactRepository.AddContactAsync(this.ChatAddress, false, this.user.PublicKeyAddress);
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

        await this.SaveParallelAcceptAsync();

        this.viewCellObject.RefreshContacts = true;
        this.isClicked = false;
      }
    }

    private async Task SaveParallelAcceptAsync()
    {
      var encryptedChatKeyToTangle = this.GenerateChatKeyToTangle();
      var saveSqlContact = this.ContactRepository.AddContactAsync(this.ChatAddress, true, this.user.PublicKeyAddress);

      var contact = new Contact
      {
        Name = Application.Current.Properties[ChiotaConstants.SettingsNameKey + this.user.PublicKeyAddress] as string,
        ImageHash = Application.Current.Properties[ChiotaConstants.SettingsImageKey + this.user.PublicKeyAddress] as string,
        ChatAddress = this.ChatAddress,
        ChatKeyAddress = this.ChatKeyAddress,
        ContactAddress = null,
        PublicKeyAddress = this.user.PublicKeyAddress,
        Rejected = false,
        Request = false,
        NtruKey = null
      };

      var chatInformationToTangle = UserService.CurrentUser.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(contact), this.ContactAddress);
      await Task.WhenAll(saveSqlContact, chatInformationToTangle, encryptedChatKeyToTangle);
    }

    private async Task<Task<bool>> GenerateChatKeyToTangle()
    {
      var contacts = await IotaHelper.GetPublicKeysAndContactAddresses(UserService.CurrentUser.TangleMessenger, this.PublicKeyAddress);
      var pasSalt = await IotaHelper.GetChatPasSalt(this.user, this.ChatKeyAddress);
      var encryptedChatPasSalt = new NtruKex(true).Encrypt(contacts[0].NtruKey, Encoding.UTF8.GetBytes(pasSalt));
      return UserService.CurrentUser.TangleMessenger.SendMessageAsync(new TryteString(encryptedChatPasSalt.EncodeBytesAsString() + ChiotaConstants.End), this.ChatKeyAddress);
    }

    public void RaisePropertyChanged([CallerMemberName] string propertyName = "")
    {
      this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
  }
}
