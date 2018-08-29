namespace Chiota.Messenger.Usecase.GetApprovedContacts
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Repository;

  /// <summary>
  /// The get approved contacts interactor.
  /// </summary>
  public class GetApprovedContactsInteractor : IUsecaseInteractor<GetApprovedContactsRequest, GetApprovedContactsResponse>
  {
    public GetApprovedContactsInteractor(IContactRepository contactRepository)
    {
      this.ContactRepository = contactRepository;
    }

    private IContactRepository ContactRepository { get; }

    /// <inheritdoc />
    public async Task<GetApprovedContactsResponse> ExecuteAsync(GetApprovedContactsRequest request)
    {
      var storedContacts = await this.ContactRepository.LoadContactsAsync(request.PublicKeyAddress.Value);

      return new GetApprovedContactsResponse { Contacts = storedContacts };
    }
  }
}