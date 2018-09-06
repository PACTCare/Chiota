namespace Chiota.ViewModels
{
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Annotations;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AcceptContact;
  using Chiota.Messenger.Usecase.DeclineContact;
  using Chiota.Models;
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
    /// Initializes a new instance of the <see cref="ContactListViewModel"/> class.
    /// </summary>
    /// <param name="acceptContactInteractor">
    /// The accept Contact Interactor.
    /// </param>
    /// <param name="declineContactInteractor">
    /// The decline Contact Interactor.
    /// </param>
    /// <param name="viewCellObject">
    /// The view cell object.
    /// </param>
    /// <param name="contact">
    /// The contact.
    /// </param>
    public ContactListViewModel(
      IUsecaseInteractor<AcceptContactRequest, AcceptContactResponse> acceptContactInteractor,
      IUsecaseInteractor<DeclineContactRequest, DeclineContactResponse> declineContactInteractor,
      ViewCellObject viewCellObject,
      Contact contact)
    {
      this.ViewCellObject = viewCellObject;
      this.Contact = contact;
      this.AcceptContactInteractor = acceptContactInteractor;
      this.DeclineContactInteractor = declineContactInteractor;
    }

    [UsedImplicitly]
    public ICommand AcceptCommand => new Command(async () => { await this.OnAccept(); });

    [UsedImplicitly]
    public ICommand DeclineCommand => new Command(async () => { await this.OnDecline(); });

    public Contact Contact { get; }

    private ViewCellObject ViewCellObject { get; }

    private IUsecaseInteractor<AcceptContactRequest, AcceptContactResponse> AcceptContactInteractor { get; }

    private IUsecaseInteractor<DeclineContactRequest, DeclineContactResponse> DeclineContactInteractor { get; }

    /// <summary>
    /// The on accept.
    /// </summary>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task OnAccept()
    {
      await this.DisplayLoadingSpinnerAsync("Accepting Contact");

      var response = await this.AcceptContactInteractor.ExecuteAsync(
                       new AcceptContactRequest
                         {
                           UserName = UserService.CurrentUser.Name,
                           UserImageHash = UserService.CurrentUser.ImageHash,
                           ChatAddress = new Address(this.Contact.ChatAddress),
                           ChatKeyAddress = new Address(this.Contact.ChatKeyAddress),
                           ContactAddress = new Address(this.Contact.ContactAddress),
                           ContactPublicKeyAddress = new Address(this.Contact.PublicKeyAddress),
                           UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                           UserKeyPair = UserService.CurrentUser.NtruKeyPair
                         });

      await this.PopPopupAsync();

      if (response.Code == ResponseCode.Success)
      {
        this.ViewCellObject.RefreshContacts = true;
      }
      else
      {
        await this.DisplayAlertAsync("Error", "An error occured while adding the contact.");
      }
    }

    /// <summary>
    /// The on decline.
    /// </summary>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task OnDecline()
    {
      await this.DisplayLoadingSpinnerAsync("Declining Contact");

      await this.DeclineContactInteractor.ExecuteAsync(
        new DeclineContactRequest
          {
            ContactChatAddress = new Address(this.Contact.ChatAddress), UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
          });

      await this.PopPopupAsync();
    }
  }
}