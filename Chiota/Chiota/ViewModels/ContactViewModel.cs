namespace Chiota.ViewModels
{
  using System.Collections.ObjectModel;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services;

  using ChatPage = Views.ChatPage;

  public class ContactViewModel : BaseViewModel
  {
    private ObservableCollection<ContactListViewModel> contactList;

    private readonly ViewCellObject viewCellObject;

    private readonly User user;

    private ContactListViewModel selectedContact;

    public ContactViewModel(User user)
    {
      this.user = user;
      this.viewCellObject = new ViewCellObject() { RefreshContacts = true };

      // needs to be removed, ressource intensive
      this.UpdateContacts();
    }


    public ContactListViewModel SelectedContact
    {
      get => this.selectedContact;
      set
      {
        if (this.selectedContact != value)
        {
          this.selectedContact = value;
          this.RaisePropertyChanged();
        }
      }
    }

    public ObservableCollection<ContactListViewModel> Contacts
    {
      get => this.contactList;
      set
      {
        this.contactList = value;
        this.RaisePropertyChanged();
      }
    }

    public async void Search(string searchInput)
    {
      this.Contacts = await this.GetConctacts(searchInput);
    }

    public async void OpenChatPage(Contact contact)
    {
      this.SelectedContact = null;
      await this.Navigation.PushAsync(new ChatPage(contact, this.user));
    }

    public async void Refreshing()
    {
      this.Contacts = await this.GetConctacts();
    }

    private async Task UpdateContacts()
    {
      while (true)
      {
        if (this.viewCellObject.RefreshContacts)
        {
          this.Contacts = await this.GetConctacts();
          this.viewCellObject.RefreshContacts = false;
        }

        await Task.Delay(3000);
      }
    }

    // Todo store contacts on device
    private async Task<ObservableCollection<ContactListViewModel>> GetConctacts(string searchText = null)
    {
      var contacts = new ObservableCollection<ContactListViewModel>();
      var searchContacts = new ObservableCollection<ContactListViewModel>();

      // right now people can add themselfs to your contacts list, when they know your public key adress and approved contact adress
      // in future store approved contacts with MAM
      var contactRequestList = await this.user.TangleMessenger.GetJsonMessageAsync<SentDataWrapper<Contact>>(this.user.RequestAddress);

      var contactApprovedList = await this.user.TangleMessenger.GetJsonMessageAsync<SentDataWrapper<Contact>>(this.user.ApprovedAddress);

      var contactsWithoutResponse = contactRequestList.Except(contactApprovedList, new ChatAdressComparer()).ToList();

      foreach (var contact in contactsWithoutResponse)
      {
        var contactCell = ViewModelConverter.ContactToViewModel(contact.Data, this.user, this.viewCellObject);
        contacts.Add(contactCell);
      }

      foreach (var contact in contactApprovedList.Where(c => !c.Data.Rejected))
      {
        contacts.Add(ViewModelConverter.ContactToViewModel(contact.Data, this.user, this.viewCellObject));
      }

      if (string.IsNullOrWhiteSpace(searchText))
      {
        return contacts;
      }

      foreach (var contact in contacts)
      {
        if (searchText != null && contact.Name.ToLower().StartsWith(searchText.ToLower()))
        {
          searchContacts.Add(contact);
        }
      }

      return searchContacts;
    }
  }
}
