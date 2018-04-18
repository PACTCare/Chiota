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

    private ContactListViewModel selectedContact;

    public ContactViewModel(User user)
    {
      this.user = user;
      viewCellObject = new ViewCellObject() { RefreshContacts = true };
    }

    public bool PageIsShown { get; set; }

    public ContactListViewModel SelectedContact
    {
      get => selectedContact;
      set
      {
        if (selectedContact != value)
        {
          selectedContact = value;
          RaisePropertyChanged();
        }
      }
    }

    public ObservableCollection<ContactListViewModel> Contacts
    {
      get => contactList;
      set
      {
        contactList = value;
        RaisePropertyChanged();
      }
    }

    public void OnAppearing()
    {
      PageIsShown = true;
      viewCellObject.RefreshContacts = true;
      this.UpdateContacts();
    }

    public void OnDisappearing()
    {
      PageIsShown = false;
    }

    public async void Search(string searchInput)
    {
      Contacts = await GetConctacts(searchInput);
    }

    public async void OpenChatPage(Contact contact)
    {
      SelectedContact = null;
      await Navigation.PushAsync(new ChatPage(contact, user));
    }

    public async void Refreshing()
    {
      Contacts = await GetConctacts();
    }

    private async Task UpdateContacts()
    {
      // var count = 0;
      while (PageIsShown)
      {
        if (viewCellObject.RefreshContacts ) 
        {
          Contacts = await GetConctacts();
          viewCellObject.RefreshContacts = false;
        }

        await Task.Delay(3000);
      }
    }

    private async Task<ObservableCollection<ContactListViewModel>> GetConctacts(string searchText = null)
    {
      var contacts = new ObservableCollection<ContactListViewModel>();
      var searchContacts = new ObservableCollection<ContactListViewModel>();

      var contactTaskList = user.TangleMessenger.GetJsonMessageAsync<Contact>(user.RequestAddress, 3);
      var approvedContactsTrytes = user.TangleMessenger.GetMessagesAsync(user.ApprovedAddress, 3);

      var contactsOnApproveAddress = IotaHelper.FilterApprovedContacts(await approvedContactsTrytes, user.NtruContactPair);
      var contactRequestList = await contactTaskList;

      var approvedContacts = contactRequestList.Intersect(contactsOnApproveAddress, new ChatAdressComparer()).ToList();

      // for immidiate refresh, when contactRequestList are already loaded and accepted clicked
      if (contactsOnApproveAddress.Count >= 1 && approvedContacts.Count == 0)
      {
        approvedContacts = Contacts.Intersect(contactsOnApproveAddress, new ChatAdressComparer()).ToList();
      }

      var contactsWithoutResponse = contactRequestList.Except(contactsOnApproveAddress, new ChatAdressComparer()).ToList();

      

      foreach (var contact in contactsWithoutResponse)
      {
        if (contact.Request)
        {
          var contactCell = ViewModelConverter.ContactToViewModel(contact, user, viewCellObject);
          contacts.Add(contactCell);
        }
      }

      foreach (var contact in approvedContacts.Where(c => !c.Rejected))
      {
        contact.Request = false;
        contacts.Add(ViewModelConverter.ContactToViewModel(contact, user, viewCellObject));
      }

      if (string.IsNullOrWhiteSpace(searchText))
      {
        return contacts;
      }

      foreach (var contact in contacts)
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
