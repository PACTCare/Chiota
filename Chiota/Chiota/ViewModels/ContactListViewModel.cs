namespace Chiota.ViewModels
{
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;

  using Xamarin.Forms;

  public class ContactListViewModel : Contact
  {
    private readonly User user;

    private readonly ViewCellObject viewCellObject;

    private bool isClicked;

    public ContactListViewModel(User user, ViewCellObject viewCellObject)
    {
      this.user = user;
      this.viewCellObject = viewCellObject;
      this.AcceptCommand = new Command(this.OnAccept);
      this.DeclineCommand = new Command(this.OnDecline);
    }

    public ICommand AcceptCommand { get; protected set; }

    public ICommand DeclineCommand { get; protected set; }

    private async void OnDecline()
    {
      if (!this.isClicked)
      {
        this.isClicked = true;

        var contact = new Contact
        {
          Name = this.Name,
          ContactAdress = this.ContactAdress,
          ImageUrl = this.ImageUrl,
          Request = false,
          Rejected = true
        };

        // store as rejected on approved contact adress
        var sentData = new SentDataWrapper<Contact> { Data = contact, Sender = this.user.Name };
        await this.user.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(sentData), this.user.ApprovedAddress);
        this.viewCellObject.RefreshContacts = true;
        this.isClicked = false;
      }
    }

    private async void OnAccept()
    {
      if (!this.isClicked)
      {
        this.isClicked = true;

        var contact = new Contact
        {
          Name = this.Name,
          ImageUrl = this.ImageUrl,
          ContactAdress = this.ContactAdress,
          ChatAdress = this.ChatAdress,
          PublicKeyAdress = this.PublicKeyAdress,
          PublicNtruKey = null,
          Request = false,
          Rejected = false
        };

        await this.SendParallelAsync(contact);
        this.viewCellObject.RefreshContacts = true;
        this.isClicked = false;
      }
    }

    // parallelize = only await for second PoW, when remote PoW 
    private Task SendParallelAsync(Contact contact)
    {
      // store as approved on own adress
      var sentData = new SentDataWrapper<Contact> { Data = contact, Sender = this.user.Name };
      var firstTransaction = this.user.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(sentData), this.user.ApprovedAddress);

      contact.Name = this.user.Name;
      contact.ImageUrl = this.user.ImageUrl;
      contact.ContactAdress = this.user.ApprovedAddress;
      contact.PublicKeyAdress = this.user.PublicKeyAddress;

      // store on other users approved contact address
      sentData = new SentDataWrapper<Contact> { Data = contact, Sender = this.user.Name };
      var secondTransaction = this.user.TangleMessenger.SendMessageAsync(IotaHelper.ObjectToTryteString(sentData), this.ContactAdress);
      return Task.WhenAll(firstTransaction, secondTransaction);
    }
  }
}
