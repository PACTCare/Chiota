namespace Chiota.Messenger.Usecase.GetContacts
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Comparison;
  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

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
        var requestedContacts = await this.LoadContactsOnAddressAsync(request.RequestAddress, request.KeyPair);
        var localApprovedContacts = await this.ContactRepository.LoadContactsAsync(request.PublicKeyAddress.Value);

        var addressComparer = new ContactComparer();
        var approvedContacts = requestedContacts.Intersect(localApprovedContacts, addressComparer).ToList();
        approvedContacts.ForEach(c => c.Request = false);

        var pendingContactRequests = requestedContacts.Union(localApprovedContacts, addressComparer).ToList()
          .Except(localApprovedContacts, addressComparer).ToList();

        if (request.DoCrossCheck)
        {
          return await this.CrossCheckAsync(request.KeyPair, request.PublicKeyAddress, approvedContacts, pendingContactRequests);
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

    private async Task<GetContactsResponse> CrossCheckAsync(
      IAsymmetricKeyPair keyPair,
      TryteString publicKeyAddress,
      List<Contact> approvedContacts,
      IEnumerable<Contact> pendingContactRequests)
    {
      var pending = new List<Contact>();
      foreach (var contactRequest in pendingContactRequests)
      {
        var contactsOnAddress = await this.LoadContactsOnAddressAsync(new Address(contactRequest.ContactAddress), keyPair);
        if (contactsOnAddress.Any(c => c.PublicKeyAddress == publicKeyAddress.Value))
        {
          await this.ContactRepository.AddContactAsync(contactRequest.ChatAddress, true, publicKeyAddress.Value);
          approvedContacts.Add(contactRequest);
        }
        else
        {
          pending.Add(contactRequest);
        }
      }

      return new GetContactsResponse { ApprovedContacts = approvedContacts, PendingContactRequests = pending, Code = ResponseCode.Success };
    }

    private async Task<List<Contact>> LoadContactsOnAddressAsync(Address contactAddress, IAsymmetricKeyPair keyPair)
    {
      var requestedContactsMessages = await this.Messenger.GetMessagesByAddressAsync(contactAddress);

      var contacts = new List<Contact>();
      foreach (var message in requestedContactsMessages)
      {
        try
        {
          var encryptedPayload = message.Payload.ToBytes();
          var decryptedPayload = NtruEncryption.Key.Decrypt(keyPair, encryptedPayload);

          contacts.Add(JsonConvert.DeserializeObject<Contact>(Encoding.UTF8.GetString(decryptedPayload)));
        }
        catch
        {
          // ignored, since invalid contact requests lead us here
        }
      }

      return contacts;
    }
  }
}