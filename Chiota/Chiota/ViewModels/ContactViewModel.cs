namespace Chiota.ViewModels
{
  using System.Collections.Generic;
  using System.Collections.ObjectModel;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Chatbot;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.GetContacts;
  using Chiota.Presenters;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;
  using Chiota.Views;

  using Models;

  using Tangle.Net.Entity;

  using ChatPage = Views.ChatPage;

  public class ContactViewModel : BaseViewModel
  {
    private ObservableCollection<ContactListViewModel> contactList;

    private ViewCellObject viewCellObject;

    private ObservableCollection<ContactListViewModel> contacts;

    private ContactListViewModel selectedContact;

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
      var bot = BotList.Bots.Find(b => b.BotSlogan == contact.ChatAddress);
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

      var interactor = DependencyResolver.Resolve<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>();
      var response = await interactor.ExecuteAsync(
                       new GetContactsRequest
                         {
                           ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
                           PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
                         });

      var contactViewModels = GetContactsPresenter.Present(response, this.viewCellObject, searchText);

      foreach (var contactViewModel in contactViewModels)
      {
        if (this.contacts.Any(c => c.Contact.ChatAddress == contactViewModel.Contact.ChatAddress))
        {
          continue;
        }

        this.contacts.Add(contactViewModel);
      }

      return new ObservableCollection<ContactListViewModel>(contactViewModels);
    }

    private void AddBotsToContacts()
    {
      if (this.contacts.Count != 0)
      {
        return;
      }

      foreach (var bot in BotList.Bots)
      {
        var botContact = new Contact
        {
          Name = bot.BotName,
          ChatAddress = bot.BotSlogan,
          ContactAddress = bot.BotSlogan,
          ImageHash = bot.ImageUrl,
          Rejected = false
        };

        this.contacts.Add(new ContactListViewModel(this.viewCellObject, botContact));
      }
    }
  }
}