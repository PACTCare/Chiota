namespace Chiota.ViewModels
{
  using System.Collections.Generic;
  using System.Collections.ObjectModel;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Chatbot;
  using Chiota.Services.UserServices;
  using Chiota.Views;

  using Models;
  using Services;

  using ChatPage = Views.ChatPage;

  public class ContactViewModel : BaseViewModel
  {
    private readonly List<BotObject> bots;

    private ObservableCollection<ContactListViewModel> contactList;

    private ViewCellObject viewCellObject;

    private ObservableCollection<ContactListViewModel> contacts;

    private ContactListViewModel selectedContact;

    public ContactViewModel()
    {
      this.bots = BotList.ReturnBotList();
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
      get => this.contactList ?? new ObservableCollection<ContactListViewModel>();
      set
      {
        this.contactList = value;
        this.RaisePropertyChanged();
      }
    }

    public async void OnAppearing()
    {
      this.contacts = new ObservableCollection<ContactListViewModel>();
      this.PageIsShown = true;
      this.viewCellObject = new ViewCellObject { RefreshContacts = true };
      await this.UpdateContacts();
    }

    public void OnDisappearing()
    {
      // resets everything, reloads new messages contacts, public key check, etc.
      UserService.CurrentUser.TangleMessenger.ShortStorageAddressList = new List<string>();
      this.PageIsShown = false;
    }

    public async void Search(string searchInput)
    {
      this.Contacts = await this.GetContacts(searchInput);
    }

    public async void OpenChatPage(Contact contact)
    {
      this.SelectedContact = null;

      // alternativ BotPage
      var bot = this.bots.Find(b => b.BotSlogan == contact.ChatAddress);
      if (bot != null)
      {
        await this.Navigation.PushAsync(new BotChatPage(bot));
      }
      else
      {
        await this.Navigation.PushAsync(new ChatPage(contact));
      }
    }

    public async void Refreshing()
    {
      this.Contacts = await this.GetContacts();
    }

    private async Task UpdateContacts()
    {
      // var count = 0;
      while (this.PageIsShown)
      {
        if (this.viewCellObject.RefreshContacts)
        {
          this.Contacts = await this.GetContacts();
          this.viewCellObject.RefreshContacts = false;
        }

        await Task.Delay(4000);
      }
    }

    private async Task<ObservableCollection<ContactListViewModel>> GetContacts(string searchText = null)
    {
      this.AddBotsToContacts();

      var searchContacts = new ObservableCollection<ContactListViewModel>();

      var contactRequestList = await UserService.CurrentUser.TangleMessenger.GetJsonMessageAsync<Contact>(UserService.CurrentUser.RequestAddress, 3);
      var contactsOnApproveAddress = await new SqLiteHelper().LoadContacts(UserService.CurrentUser.PublicKeyAddress);

      // all infos are taken from contactRequestList
      var approvedContacts = contactRequestList.Intersect(contactsOnApproveAddress, new ChatAdressComparer()).ToList();

      // decline info is stored on contactsOnApproveAddress
      foreach (var approved in approvedContacts)
      {
        foreach (var c in contactsOnApproveAddress)
        {
          if (approved.ChatAddress == c.ChatAddress)
          {
            approved.Rejected = c.Rejected;
          }
        }
      }

      if (this.Contacts != null && contactsOnApproveAddress.Count == 1 && approvedContacts.Count == 0)
      {
        // imidiate refresh, wehn decline is clicked
        if (contactsOnApproveAddress[0].Rejected)
        {
          this.RemoveAddress(contactsOnApproveAddress[0].ChatAddress);
        }
        else
        {
          // for immidiate refresh, when contactRequestList are already loaded and accepted clicked
          approvedContacts = this.Contacts.Intersect(contactsOnApproveAddress, new ChatAdressComparer()).ToList();
        }
      }

      var contactsWithoutResponse = contactRequestList.Except(contactsOnApproveAddress, new ChatAdressComparer()).ToList();

      foreach (var contact in contactsWithoutResponse)
      {
        if (contact.Request)
        {
          var contactCell = ViewModelConverter.ContactToViewModel(contact, UserService.CurrentUser, this.viewCellObject);
          this.contacts.Add(contactCell);
        }
      }

      foreach (var contact in approvedContacts.Where(c => !c.Rejected))
      {
        contact.Request = false;
        this.RemoveAddress(contact.ChatAddress);
        this.contacts.Add(ViewModelConverter.ContactToViewModel(contact, UserService.CurrentUser, this.viewCellObject));
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

    private void RemoveAddress(string chatAddress)
    {
      var itemToRemove = this.contacts.SingleOrDefault(r => r.ChatAddress.Contains(chatAddress));
      if (itemToRemove == null)
      {
        return;
      }

      try
      {
        this.contacts.Remove(itemToRemove);
      }
      catch
      {
        // ignored
      }
    }

    private void AddBotsToContacts()
    {
      if (this.contacts.Count != 0)
      {
        return;
      }

      foreach (var bot in this.bots)
      {
        var botContact = new Contact
                           {
                             Name = bot.BotName,
                             ChatAddress = bot.BotSlogan,
                             ContactAddress = bot.BotSlogan,
                             ImageUrl = bot.ImageUrl,
                             Rejected = false
                           };

        this.contacts.Add(ViewModelConverter.ContactToViewModel(botContact, UserService.CurrentUser, this.viewCellObject));
      }
    }
  }
}
