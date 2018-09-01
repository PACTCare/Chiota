namespace Chiota.Messenger.Usecase.AcceptContact
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  /// <summary>
  /// The accept contact interactor.
  /// </summary>
  public class AcceptContactInteractor : AbstractContactInteractor<AcceptContactRequest, AcceptContactResponse>
  {
    /// <inheritdoc />
    public AcceptContactInteractor(IContactRepository repository, IMessenger messenger)
      : base(repository, messenger)
    {
    }

    /// <inheritdoc />
    public override async Task<AcceptContactResponse> ExecuteAsync(AcceptContactRequest request)
    {
      var contactDetails = new Contact();

      var contactInformation = await this.Repository.LoadContactInformationByAddressAsync(request.ContactPublicKeyAddress);

      await this.SendContactDetails(MessageType.AcceptContact, contactDetails, contactInformation.ContactAddress);
      await this.ExchangeKey(contactDetails, contactInformation);

      await this.Repository.AddContactAsync(request.ChatAddress.Value, true, contactDetails.PublicKeyAddress);

      return null;
    }
  }
}