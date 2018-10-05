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

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

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
        var requestedContacts = await this.LoadContactsOnAddressAsync(request.ContactRequestAddress);
        var localApprovedContacts = await this.ContactRepository.LoadContactsAsync(request.PublicKeyAddress.Value);

        var addressComparer = new ContactComparer();
        var approvedContacts = requestedContacts.Intersect(localApprovedContacts, addressComparer).ToList();
        approvedContacts.ForEach(c => c.Request = false);

        var pendingContactRequests = requestedContacts.Union(localApprovedContacts, addressComparer).ToList()
          .Except(localApprovedContacts, addressComparer).ToList();

        if (request.DoCrossCheck)
        {
          return await this.CrossCheckAsync(request.PublicKeyAddress, approvedContacts, pendingContactRequests);
        }

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

    private async Task<GetContactsResponse> CrossCheckAsync(Address publicKeyAddress, List<Contact> approvedContacts, IEnumerable<Contact> pendingContactRequests)
    {
      var pending = new List<Contact>();
      foreach (var pendingContactRequest in pendingContactRequests)
      {
        var contactsOnAddress = await this.LoadContactsOnAddressAsync(new Address(pendingContactRequest.ContactAddress));
        if (contactsOnAddress.Any(c => c.PublicKeyAddress == publicKeyAddress.Value))
        {
          approvedContacts.Add(pendingContactRequest);
        }
        else
        {
          pending.Add(pendingContactRequest);
        }
      }

      return new GetContactsResponse
               {
                 ApprovedContacts = approvedContacts, PendingContactRequests = pending, Code = ResponseCode.Success
               };
    }

    private async Task<List<Contact>> LoadContactsOnAddressAsync(Address contactAddress)
    {
      var requestedContactsMessages = await this.Messenger.GetMessagesByAddressAsync(contactAddress);
      return requestedContactsMessages.Select(m => JsonConvert.DeserializeObject<Contact>(m.Payload.ToUtf8String())).ToList();
    }
  }
}