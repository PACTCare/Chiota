namespace Chiota.ViewModels
{
  using System.Collections.ObjectModel;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services;

  public class ContactViewModel : BaseViewModel
  {
    private ObservableCollection<ContactListViewModel> contactListList;

    private readonly User user;

    public ContactViewModel(User user)
    {
      this.user = user;
      this.UpdateContacts();
    }

    public ObservableCollection<ContactListViewModel> Contacts
    {
      get => this.contactListList;
      set
      {
        this.contactListList = value;
        this.RaisePropertyChanged();
      }
    }

    public void Search(string searchInput)
    {
      this.Contacts = this.GetConctacts(searchInput);
    }

    public void Refreshing()
    {
      this.Contacts = this.GetConctacts();
    }

    private async Task UpdateContacts()
    {
      while (true)
      {
        this.Contacts = this.GetConctacts();
        await Task.Delay(20000);
      }
    }

    private ObservableCollection<ContactListViewModel> GetConctacts(string searchText = null)
    {
      var contacts = new ObservableCollection<ContactListViewModel>();
      var searchContacts = new ObservableCollection<ContactListViewModel>();

      // right now people can add themselfs to your contacts list, when they know your public key adress and approved contact adress
      // in future store approved contact with MAM
      var contactRequestList = this.user.TangleMessenger.GetJsonMessage<SentDataWrapper<Contact>>(this.user.RequestAddress);
      var contactApprovedList = this.user.TangleMessenger.GetJsonMessage<SentDataWrapper<Contact>>(this.user.ApprovedAddress);

      var contactsWithoutResponse = contactRequestList.Except(contactApprovedList, new ChatAdressComparer()).ToList();

      foreach (var contact in contactsWithoutResponse)
      {
        contacts.Add(ViewModelConverter.ContactToViewModel(contact.Data, this.user));
      }

      foreach (var contact in contactApprovedList.Where(c => !c.Data.Rejected))
      {
        contacts.Add(ViewModelConverter.ContactToViewModel(contact.Data, this.user));
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
