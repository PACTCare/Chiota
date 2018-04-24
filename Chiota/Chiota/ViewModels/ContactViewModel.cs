namespace Chiota.ViewModels
{
  using System.Collections.ObjectModel;
  using System.Linq;
  using System.Threading.Tasks;

  using IOTAServices;
  using Models;
  using Services;

  using ChatPage = Views.ChatPage;

  public class ContactViewModel : BaseViewModel
  {
    private ObservableCollection<ContactListViewModel> contactList;

    private readonly ViewCellObject viewCellObject;

    private readonly User user;

    private readonly ObservableCollection<ContactListViewModel> contacts;

    private ContactListViewModel selectedContact;

    public ContactViewModel(User user)
    {
      this.contacts = new ObservableCollection<ContactListViewModel>();
      this.user = user;
      this.viewCellObject = new ViewCellObject() { RefreshContacts = true };
    }

    public bool PageIsShown { get; set; }

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

    public void OnAppearing()
    {
      this.PageIsShown = true;
      this.viewCellObject.RefreshContacts = true;
      this.UpdateContacts();
    }

    public void OnDisappearing()
    {
      this.PageIsShown = false;
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
      // var count = 0;
      while (this.PageIsShown)
      {
        if (this.viewCellObject.RefreshContacts)
        {
          this.Contacts = await this.GetConctacts();
          this.viewCellObject.RefreshContacts = false;
        }

        await Task.Delay(5000);
      }
    }

    private async Task<ObservableCollection<ContactListViewModel>> GetConctacts(string searchText = null)
    {
      var searchContacts = new ObservableCollection<ContactListViewModel>();

      var contactTaskList = this.user.TangleMessenger.GetJsonMessageAsync<Contact>(this.user.RequestAddress, 3);
      var approvedContactsTrytes = this.user.TangleMessenger.GetMessagesAsync(this.user.ApprovedAddress, 3);

      var contactsOnApproveAddress = IotaHelper.FilterApprovedContacts(await approvedContactsTrytes, this.user.NtruContactPair);
      var contactRequestList = await contactTaskList;

      var approvedContacts = contactRequestList.Intersect(contactsOnApproveAddress, new ChatAdressComparer()).ToList();

      // for immidiate refresh, when contactRequestList are already loaded and accepted clicked
      if (contactsOnApproveAddress.Count >= 1 && approvedContacts.Count == 0)
      {
        approvedContacts = this.Contacts.Intersect(contactsOnApproveAddress, new ChatAdressComparer()).ToList();
      }

      var contactsWithoutResponse = contactRequestList.Except(contactsOnApproveAddress, new ChatAdressComparer()).ToList();

      foreach (var contact in contactsWithoutResponse)
      {
        if (contact.Request)
        {
          var contactCell = ViewModelConverter.ContactToViewModel(contact, this.user, this.viewCellObject);
          this.contacts.Add(contactCell);
        }
      }

      foreach (var contact in approvedContacts.Where(c => !c.Rejected))
      {
        contact.Request = false;

        // remove request from list
        var itemToRemove = this.contacts.SingleOrDefault(r => r.ChatAdress.Contains(contact.ChatAdress));
        if (itemToRemove != null)
        {
          this.contacts.Remove(itemToRemove);
        }

        this.contacts.Add(ViewModelConverter.ContactToViewModel(contact, this.user, this.viewCellObject));
      }

      if (string.IsNullOrWhiteSpace(searchText))
      {
        return this.contacts;
      }

      foreach (var contact in this.contacts)
      {
        if (contact.Name.ToLower().StartsWith(searchText.ToLower()))
        {
          searchContacts.Add(contact);
        }
      }

      return searchContacts;
    }
  }
}
