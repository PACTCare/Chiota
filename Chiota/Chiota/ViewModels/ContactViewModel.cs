using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
  using System.Collections.Generic;
  using System.Collections.ObjectModel;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Chatbot;
  using Chiota.Messenger.Comparison;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.GetContacts;
  using Chiota.Persistence;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;
  using Chiota.Views;

  using Models;
  using Services;

  using Tangle.Net.Entity;

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

      var interactor = DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>();
      var response = await interactor.ExecuteAsync(
                       new GetContactsRequest
                         {
                           ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                           PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
                         });

      // TODO: Below in a presenter and duplicate code removing
      foreach (var contact in response.PendingContactRequests)
      {
        if (this.contacts.Any(c => c.ChatAddress == contact.ChatAddress))
        {
          continue;
        }

        this.contacts.Add(ViewModelConverter.ContactToViewModel(contact, UserService.CurrentUser, this.viewCellObject));
      }

      foreach (var contact in response.ApprovedContacts)
      {
        if (this.contacts.Any(c => c.ChatAddress == contact.ChatAddress))
        {
          continue;
        }

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
          ImageHash = bot.ImageUrl,
          Rejected = false
        };

        this.contacts.Add(ViewModelConverter.ContactToViewModel(botContact, UserService.CurrentUser, this.viewCellObject));
      }
    }
  }
}