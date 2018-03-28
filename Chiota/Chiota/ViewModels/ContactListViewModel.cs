namespace Chiota.ViewModels
{
  using System.Windows.Input;

  using Chiota.Models;

  using Xamarin.Forms;

  public class ContactListViewModel : Contact
  {
    private readonly User user;

    private bool isClicked;

    public ContactListViewModel(User user)
    {
      this.user = user;
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
        await this.user.TangleMessenger.SendJsonMessageAsync(new SentDataWrapper<Contact> { Data = contact, Sender = this.user.Name }, this.user.ApprovedAddress);
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

        // store as approved on own adress
        await this.user.TangleMessenger.SendJsonMessageAsync(new SentDataWrapper<Contact> { Data = contact, Sender = this.user.Name }, this.user.ApprovedAddress);

        contact.Name = this.user.Name;
        contact.ImageUrl = this.user.ImageUrl;
        contact.ContactAdress = this.user.ApprovedAddress;
        contact.PublicKeyAdress = this.user.PublicKeyAddress;

        // store on other users approved contact address
        await this.user.TangleMessenger.SendJsonMessageAsync(new SentDataWrapper<Contact> { Data = contact, Sender = this.user.Name }, this.ContactAdress);

        this.isClicked = false;
      }
    }
  }
}
