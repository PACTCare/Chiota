namespace Chiota.Messenger.Usecase.GetContacts
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Comparison;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;

  using Newtonsoft.Json;

  /// <summary>
  ///   The get approved contacts interactor.
  /// </summary>
  public class GetContactsInteractor : IUsecaseInteractor<GetContactsRequest, GetContactsResponse>
  {
    public GetContactsInteractor(IContactRepository contactRepository, IMessenger messenger)
    {
      this.ContactRepository = contactRepository;
      this.Messenger = messenger;
    }

    private IContactRepository ContactRepository { get; }

    private IMessenger Messenger { get; }

    /// <inheritdoc />
    public async Task<GetContactsResponse> ExecuteAsync(GetContactsRequest request)
    {
      try
      {
        var requestedContactsMessages = await this.Messenger.GetMessagesByAddressAsync(request.ContactRequestAddress, new ChatMessageBundleParser());
        var requestedContacts = requestedContactsMessages.Select(m => JsonConvert.DeserializeObject<Contact>(m.Payload.ToUtf8String())).ToList();
        var localApprovedContacts = await this.ContactRepository.LoadContactsAsync(request.PublicKeyAddress.Value);

        var addressComparer = new ContactComparer();
        var pendingContactRequests = requestedContacts.Union(localApprovedContacts, addressComparer).ToList()
          .Except(localApprovedContacts, addressComparer).ToList();

        var approvedContacts = requestedContacts.Intersect(localApprovedContacts, addressComparer).ToList();
        approvedContacts.ForEach(c => c.Request = false);

        return new GetContactsResponse
                 {
                   ApprovedContacts = approvedContacts, PendingContactRequests = pendingContactRequests, Code = ResponseCode.Success
                 };
      }
      catch (Exception)
      {
        return new GetContactsResponse { Code = ResponseCode.ContactsUnavailable };
      }
    }
  }
}