namespace Chiota.ViewModels
{
  using System;
  using System.Collections.Generic;
  using System.Collections.ObjectModel;
  using System.Diagnostics;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Chatbot;
  using Chiota.Views;

  using IOTAServices;
  using Models;
  using Services;

  using ChatPage = Views.ChatPage;

  public class ContactViewModel : BaseViewModel
  {
    private ObservableCollection<ContactListViewModel> contactList;

    private readonly ViewCellObject viewCellObject;

    private readonly User user;

    private readonly List<BotObject> bots;

    private ObservableCollection<ContactListViewModel> contacts;

    private ContactListViewModel selectedContact;

    public ContactViewModel(User user)
    {
      this.bots = new List<BotObject>();

      // Add your own microsoft bot-framework bot here:
      //this.bots.Add(new BotObject()
      //{
      //  BotName = "Florence",
      //  BotSlogan = "Your health assistant",
      //  BotId = "Florence",
      //  DirectLineSecret = "", // <= your direct line secret
      //  ImageUrl = "https://florenceblob.blob.core.windows.net/thumbnails/final_verysmall2.png"
      //});

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
      this.contacts = new ObservableCollection<ContactListViewModel>();
      this.UpdateContacts();
    }

    public void OnDisappearing()
    {
      // resets everything, reloads new messages contacts, public key check, etc.
      this.user.TangleMessenger.ShortStorageAddressList = new List<string>();
      this.PageIsShown = false;
    }

    public async void Search(string searchInput)
    {
      this.Contacts = await this.GetConctacts(searchInput);
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
        await this.Navigation.PushAsync(new ChatPage(contact, this.user));
      }
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
      this.AddBotsToContacts();

      var searchContacts = new ObservableCollection<ContactListViewModel>();

      var contactTaskList = this.user.TangleMessenger.GetJsonMessageAsync<Contact>(this.user.RequestAddress, 3);
      var approvedContactsTrytes = this.user.TangleMessenger.GetMessagesAsync(this.user.ApprovedAddress, 3);

      var contactsOnApproveAddress = IotaHelper.FilterApprovedContacts(await approvedContactsTrytes, this.user.NtruContactPair);
      var contactRequestList = await contactTaskList;

      // all infos are taken from contactRequestList
      var approvedContacts = contactRequestList.Intersect(contactsOnApproveAddress, new ChatAdressComparer()).ToList();

      // decline info is stored on contactsOnApproveAddress
      for (int i = 0; i < approvedContacts.Count; i++)
      {
        foreach (var c in contactsOnApproveAddress)
        {
          if (approvedContacts[i].ChatAddress == c.ChatAddress)
          {
            approvedContacts[i].Rejected = c.Rejected;
          }
        }
      }

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
        var itemToRemove = this.contacts.SingleOrDefault(r => r.ContactAddress.Contains(contact.ContactAddress));
        if (itemToRemove != null)
        {
          try
          {
            this.contacts.Remove(itemToRemove);
          }
          catch (Exception e)
          {
            Trace.WriteLine(e);
          }
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

    private void AddBotsToContacts()
    {
      if (this.contacts.Count == 0)
      {
        foreach (var b in this.bots)
        {
          var botContact = new Contact()
          {
            Name = b.BotName,
            ChatAddress = b.BotSlogan,
            ContactAddress = b.BotSlogan,
            ImageUrl = b.ImageUrl,
            Rejected = false
          };
          this.contacts.Add(ViewModelConverter.ContactToViewModel(botContact, this.user, this.viewCellObject));
        }
      }
    }
  }
}
