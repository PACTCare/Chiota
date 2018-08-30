namespace Chiota.Messenger.Tests.Usecase
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Tests.Cache;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.GetContacts;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Moq;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.DataTransfer;
  using Tangle.Net.Utils;

  using Constants = Chiota.Messenger.Constants;

  /// <summary>
  /// The get approved contacts interactor test.
  /// </summary>
  [TestClass]
  public class GetContactsInteractorTest
  {
    /// <summary>
    /// The test no contacts exist should return empty list.
    /// </summary>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    [TestMethod]
    public async Task TestNoContactsExistShouldReturnEmptyList()
    {
      var interactor = new GetContactsInteractor(new InMemoryContactRepository(), new InMemoryTransactionCache(), new InMemoryIotaRepository());
      var response = await interactor.ExecuteAsync(new GetContactsRequest { PublicKeyAddress = new Address(Hash.Empty.Value) });

      Assert.AreEqual(0, response.ApprovedContacts.Count);
    }

    [TestMethod]
    public async Task TestContactsAreContainedCachedAndApproved()
    {
      var pubKeyAddress = Seed.Random().Value;
      var contactRequestAddress = new Address(Seed.Random().Value);
      var storedContactAddress = Seed.Random().Value;

      var contactRepository = new InMemoryContactRepository();
      var transactionCache = new InMemoryTransactionCache();

      var cacheItem = new TransactionCacheItem
                                   {
                                     Address = contactRequestAddress,
                                     TransactionHash = new Hash(Seed.Random().Value),
                                     TransactionTrytes = TryteString.FromUtf8String(
                                       JsonConvert.SerializeObject(
                                         new Contact { ChatAddress = storedContactAddress }))
                                   };

      await transactionCache.SaveTransactionAsync(cacheItem);
      await contactRepository.AddContactAsync(storedContactAddress, true, pubKeyAddress);

      var iotaRepositoryMock = new Mock<IIotaRepository>();
      iotaRepositoryMock.Setup(i => i.FindTransactionsByAddressesAsync(It.IsAny<List<Address>>())).ReturnsAsync(
        new TransactionHashList { Hashes = new List<Hash> { cacheItem.TransactionHash } });

      var interactor = new GetContactsInteractor(contactRepository, transactionCache, iotaRepositoryMock.Object);
      var response = await interactor.ExecuteAsync(
                       new GetContactsRequest
                         {
                           PublicKeyAddress = new Address(pubKeyAddress),
                           ContactRequestAddress = contactRequestAddress
                         });

      Assert.AreEqual(1, response.ApprovedContacts.Count);
    }

    [TestMethod]
    public async Task TestContactsAreNotCachedButOnTangleShouldExcludeRejectedContactsAndSetCache()
    {
      var pubKeyAddress = Seed.Random().Value;
      var contactRequestAddress = new Address(Seed.Random().Value);
      var rejectedContactAddress = Seed.Random().Value;
      var storedContactAddress = Seed.Random().Value;

      var contactRepository = new InMemoryContactRepository();
      await contactRepository.AddContactAsync(storedContactAddress, true, pubKeyAddress);

      var approvedContactMessage = TryteString.FromUtf8String(JsonConvert.SerializeObject(new Contact { ChatAddress = storedContactAddress }));

      var rejectedContactBundle = CreateBundle(
        contactRequestAddress,
        TryteString.FromUtf8String(JsonConvert.SerializeObject(new Contact { ChatAddress = rejectedContactAddress, Rejected = true })));

      var approvedContactBundle = CreateBundle(contactRequestAddress, approvedContactMessage);

      var iotaRepository = new InMemoryIotaRepository();
      iotaRepository.SentBundles.Add(rejectedContactBundle);
      iotaRepository.SentBundles.Add(approvedContactBundle);
      iotaRepository.SentBundles.Add(
        CreateBundle(
          contactRequestAddress,
          TryteString.FromUtf8String(JsonConvert.SerializeObject(new Contact { ChatAddress = storedContactAddress, Request = true }))));

      var transactionCache = new InMemoryTransactionCache();

      var cacheItem = new TransactionCacheItem
                        {
                          Address = contactRequestAddress,
                          TransactionHash = approvedContactBundle.Transactions[0].Hash,
                          TransactionTrytes = approvedContactMessage
      };

      transactionCache.Items.Add(cacheItem);

      var interactor = new GetContactsInteractor(contactRepository, transactionCache, iotaRepository);
      var response = await interactor.ExecuteAsync(
                       new GetContactsRequest
                         {
                           PublicKeyAddress = new Address(pubKeyAddress),
                           ContactRequestAddress = contactRequestAddress
                         });

      Assert.AreEqual(1, response.ApprovedContacts.Count);
      Assert.AreEqual(1, response.PendingContactRequests.Count);
      Assert.AreEqual(3, transactionCache.Items.Count);
    }

    private static Bundle CreateBundle(Address contactRequestAddress, TryteString rejectedContactMessage)
    {
      var rejectedContactBundle = new Bundle();
      rejectedContactBundle.AddTransfer(
        new Transfer
          {
            Address = contactRequestAddress,
            Message = rejectedContactMessage,
            Timestamp = Timestamp.UnixSecondsTimestamp,
            Tag = Constants.Tag
          });

      rejectedContactBundle.Finalize();
      rejectedContactBundle.Sign();

      // calculate hashes
      var transactions = rejectedContactBundle.Transactions;
      rejectedContactBundle.Transactions = transactions.Select(t => Transaction.FromTrytes(t.ToTrytes())).ToList();
      return rejectedContactBundle;
    }

    [TestMethod]
    public async Task TestExceptionGetsThrownShouldReturnErrorCode()
    {
      var interactor = new GetContactsInteractor(new ExceptionContactRepository(), new InMemoryTransactionCache(), new InMemoryIotaRepository());
      var response = await interactor.ExecuteAsync(new GetContactsRequest { PublicKeyAddress = new Address(Hash.Empty.Value) });

      Assert.AreEqual(ResponseCode.ContactsUnavailable, response.Code);
    }
  }
}