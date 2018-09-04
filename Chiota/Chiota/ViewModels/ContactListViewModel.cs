namespace Chiota.ViewModels
{
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AcceptContact;
  using Chiota.Models;
  using Chiota.Persistence;
  using Chiota.Popups.PopupModels;
  using Chiota.Popups.PopupPageModels;
  using Chiota.Popups.PopupPages;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;

  using Tangle.Net.Entity;

  using Xamarin.Forms;

  /// <summary>
  /// The contact list view model.
  /// </summary>
  public class ContactListViewModel : BaseViewModel
  {
    /// <summary>
    /// The view cell object.
    /// </summary>
    private readonly ViewCellObject viewCellObject;

    /// <summary>
    /// The is clicked.
    /// </summary>
    private bool isClicked;

    /// <summary>
    /// Initializes a new instance of the <see cref="ContactListViewModel"/> class.
    /// </summary>
    /// <param name="viewCellObject">
    /// The view cell object.
    /// </param>
    /// <param name="contact">
    /// The contact.
    /// </param>
    public ContactListViewModel(ViewCellObject viewCellObject, Contact contact)
    {
      this.viewCellObject = viewCellObject;
      this.Contact = contact;
      this.ContactRepository = DependencyResolver.Resolve<AbstractSqlLiteContactRepository>();
    }

    public ICommand AcceptCommand => new Command(async () => { await this.OnAccept(); });

    public ICommand DeclineCommand => new Command(async () => { await this.OnDecline(); });

    public Contact Contact { get; }

    /// <summary>
    /// Gets the contact repository.
    /// </summary>
    private AbstractSqlLiteContactRepository ContactRepository { get; }

    /// <summary>
    /// The on accept.
    /// </summary>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task OnAccept()
    {
      await this.PushPopupAsync<LoadingPopupPageModel, LoadingPopupModel>(
        new LoadingPopupPage(),
        new LoadingPopupModel { Message = "Accepting Contact" });

      var request = new AcceptContactRequest
                      {
                        UserName =
                          Application.Current.Properties[ChiotaConstants.SettingsNameKey + UserService.CurrentUser.PublicKeyAddress] as string,
                        UserImageHash =
                          Application.Current.Properties[ChiotaConstants.SettingsImageKey + UserService.CurrentUser.PublicKeyAddress] as string,
                        ChatAddress = new Address(this.Contact.ChatAddress),
                        ChatKeyAddress = new Address(this.Contact.ChatKeyAddress),
                        ContactAddress = new Address(this.Contact.ContactAddress),
                        ContactPublicKeyAddress = new Address(this.Contact.PublicKeyAddress),
                        UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                        UserKeyPair = UserService.CurrentUser.NtruKeyPair
                      };

      var interactor = DependencyResolver.Resolve<IUsecaseInteractor<AcceptContactRequest, AcceptContactResponse>>();
      await interactor.ExecuteAsync(request);

      this.viewCellObject.RefreshContacts = true;
      await this.PopPopupAsync();
    }

    /// <summary>
    /// The on decline.
    /// </summary>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task OnDecline()
    {
      if (!this.isClicked)
      {
        this.isClicked = true;
        await this.ContactRepository.AddContactAsync(this.Contact.ChatAddress, false, UserService.CurrentUser.PublicKeyAddress);
        this.viewCellObject.RefreshContacts = true;
        this.isClicked = false;
      }
    }
  }
}