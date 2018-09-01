namespace Chiota.Messenger.Usecase.GetContacts
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Comparison;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;

  /// <summary>
  ///   The get approved contacts interactor.
  /// </summary>
  public class
    GetContactsInteractor : IUsecaseInteractor<GetContactsRequest, GetContactsResponse>
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="GetContactsInteractor"/> class.
    /// </summary>
    /// <param name="contactRepository">
    /// The contact repository.
    /// </param>
    /// <param name="transactionCache">
    /// The transaction cache.
    /// </param>
    /// <param name="iotaRepository">
    /// The iota repository.
    /// </param>
    public GetContactsInteractor(
      IContactRepository contactRepository,
      ITransactionCache transactionCache,
      IIotaRepository iotaRepository)
    {
      this.ContactRepository = contactRepository;
      this.TransactionCache = transactionCache;
      this.IotaRepository = iotaRepository;
    }

    /// <summary>
    /// Gets the contact repository.
    /// </summary>
    private IContactRepository ContactRepository { get; }

    /// <summary>
    /// Gets the iota repository.
    /// </summary>
    private IIotaRepository IotaRepository { get; }

    /// <summary>
    /// Gets the transaction cache.
    /// </summary>
    private ITransactionCache TransactionCache { get; }

    /// <inheritdoc />
    public async Task<GetContactsResponse> ExecuteAsync(GetContactsRequest request)
    {
      try
      {
        var requestedContacts = await this.LoadContactRequests(request.ContactRequestAddress);
        var localApprovedContacts = await this.ContactRepository.LoadContactsAsync(request.PublicKeyAddress.Value);

        var addressComparer = new ChatAddressComparer();
        var pendingContactRequests = requestedContacts.Union(localApprovedContacts, addressComparer).ToList()
          .Except(localApprovedContacts, addressComparer).ToList();

        // Request does not get updated so we need to set it here. TODO: Find a way to do this another way
        var approvedContacts = requestedContacts.Intersect(localApprovedContacts, addressComparer).ToList();
        approvedContacts.ForEach(c => c.Request = false);

        return new GetContactsResponse
                 {
                   ApprovedContacts = approvedContacts,
                   PendingContactRequests = pendingContactRequests,
                   Code = ResponseCode.Success
                 };
      }
      catch (Exception)
      {
        return new GetContactsResponse { Code = ResponseCode.ContactsUnavailable };
      }
    }

    /// <summary>
    /// The load contacts from tangle.
    /// </summary>
    /// <param name="address">
    /// The address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task<List<Contact>> LoadContactRequests(Address address)
    {
      var contacts = new List<Contact>();

      var cachedTransactions = await this.TransactionCache.LoadTransactionsByAddressAsync(address);
      foreach (var cachedTransaction in cachedTransactions)
      {
        contacts.Add(JsonConvert.DeserializeObject<Contact>(cachedTransaction.TransactionTrytes.ToUtf8String()));
      }

      var transactionHashesFromTangle = await this.IotaRepository.FindTransactionsByAddressesAsync(new List<Address> { address });

      foreach (var transactionHash in transactionHashesFromTangle.Hashes)
      {
        if (cachedTransactions.Any(h => h.TransactionHash.Value == transactionHash.Value))
        {
          continue;
        }

        var bundle = await this.IotaRepository.GetBundleAsync(transactionHash);
        foreach (var message in bundle.GetMessages())
        {
          await this.TransactionCache.SaveTransactionAsync(
            new TransactionCacheItem
              {
                Address = address,
                TransactionHash = transactionHash,
                TransactionTrytes = TryteString.FromUtf8String(message)
              });

          contacts.Add(JsonConvert.DeserializeObject<Contact>(message));
        }
      }

      return contacts;
    }
  }
}