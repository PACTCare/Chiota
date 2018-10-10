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
    public GetContactsInteractor(IContactRepository contactRepository, IMessenger messenger, IEncryption encryption)
    {
      this.ContactRepository = contactRepository;
      this.Messenger = messenger;
      this.Encryption = encryption;
    }

    private IContactRepository ContactRepository { get; }

    private IMessenger Messenger { get; }

    private IEncryption Encryption { get; }

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
        var requestedContactsMessages = await this.Messenger.GetMessagesByAddressAsync(new Address(contactRequest.ContactAddress));
        if (this.TryParseNonces(keyPair, requestedContactsMessages))
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

    private bool TryParseNonces(IAsymmetricKeyPair keyPair, List<Message> requestedContactsMessages)
    {
      foreach (var message in requestedContactsMessages)
      {
        try
        {
          var encryptedNonce = new TryteString(
            message.Payload.Value.Substring(
              message.Payload.Value.IndexOf(Constants.LineBreak.Value, StringComparison.Ordinal) + Constants.LineBreak.TrytesLength));

          var nonce = this.Encryption.Decrypt(keyPair, encryptedNonce.ToBytes());
          return DateTime.TryParse(Encoding.UTF8.GetString(nonce), out _);
        }
        catch
        {
          // ignored
        }
      }

      return false;
    }

    private async Task<List<Contact>> LoadContactsOnAddressAsync(Address contactAddress, IAsymmetricKeyPair keyPair)
    {
      var requestedContactsMessages = await this.Messenger.GetMessagesByAddressAsync(contactAddress);

      var contacts = new List<Contact>();
      foreach (var message in requestedContactsMessages)
      {
        try
        {
          var contactPayload = message.Payload.GetChunk(0, message.Payload.Value.IndexOf(Constants.LineBreak.Value, StringComparison.Ordinal));
          var decryptedPayload = this.Encryption.Decrypt(keyPair, contactPayload.ToBytes());

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