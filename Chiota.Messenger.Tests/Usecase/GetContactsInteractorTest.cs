namespace Chiota.Messenger.Tests.Usecase
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Tests.Encryption;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Tests.Service;
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
      var interactor = new GetContactsInteractor(new InMemoryContactRepository(), new InMemoryMessenger(), new EncryptionStub());
      var response = await interactor.ExecuteAsync(new GetContactsRequest { PublicKeyAddress = new Address(Hash.Empty.Value) });

      Assert.AreEqual(0, response.ApprovedContacts.Count);
    }

    [TestMethod]
    public async Task TestContactsAreContainedCachedAndApproved()
    {
      var pubKeyAddress = Seed.Random().Value;
      var contactRequestAddress = new Address(Seed.Random().Value);
      var storedContactAddress = Seed.Random().Value;
      var keyPair = InMemoryContactRepository.NtruKeyPair;

      var contactRepository = new InMemoryContactRepository();
      var transactionCache = new InMemoryTransactionCache();

      var bundle = CreateBundle(
        contactRequestAddress,
        ContactExchange.Create(new Contact { ChatAddress = storedContactAddress, Rejected = true }, keyPair.PublicKey, keyPair.PublicKey).Payload);

      bundle.Transactions.ForEach(async t => await transactionCache.SaveTransactionAsync(new TransactionCacheItem
                                                                                     {
                                                                                       Address = contactRequestAddress,
                                                                                       TransactionHash = t.Hash,
                                                                                       TransactionTrytes = t.ToTrytes()
                                                                                     }));

      await contactRepository.AddContactAsync(storedContactAddress, true, pubKeyAddress);

      var iotaRepositoryMock = new Mock<IIotaRepository>();
      iotaRepositoryMock.Setup(i => i.FindTransactionsByAddressesAsync(It.IsAny<List<Address>>())).ReturnsAsync(
        new TransactionHashList { Hashes = new List<Hash>(bundle.Transactions.Select(t => t.Hash)) });
      iotaRepositoryMock.Setup(i => i.GetTrytesAsync(It.IsAny<List<Hash>>())).ReturnsAsync(new List<TransactionTrytes>());

      var interactor = new GetContactsInteractor(contactRepository, new TangleMessenger(iotaRepositoryMock.Object, transactionCache), NtruEncryption.Key);
      var response = await interactor.ExecuteAsync(
                       new GetContactsRequest
                         {
                           PublicKeyAddress = new Address(pubKeyAddress),
                           RequestAddress = contactRequestAddress,
                           KeyPair = keyPair
                       });

      Assert.AreEqual(1, response.ApprovedContacts.Count);
    }

    [TestMethod]
    public async Task TestContactsAreCachedAndOnTangleShouldExcludeRejectedContactsAndSetCache()
    {
      var pubKeyAddress = Seed.Random().Value;
      var contactRequestAddress = new Address(Seed.Random().Value);
      var rejectedContactAddress = Seed.Random().Value;
      var storedContactAddress = Seed.Random().Value;
      var keyPair = InMemoryContactRepository.NtruKeyPair;

      var contactRepository = new InMemoryContactRepository();
      await contactRepository.AddContactAsync(storedContactAddress, true, pubKeyAddress);
      await contactRepository.AddContactAsync(rejectedContactAddress, false, pubKeyAddress);

      var rejectedContactBundle = CreateBundle(
        contactRequestAddress,
        ContactExchange.Create(new Contact { ChatAddress = rejectedContactAddress, Rejected = true }, keyPair.PublicKey, keyPair.PublicKey).Payload);

      var approvedContactBundle = CreateBundle(
        contactRequestAddress,
        ContactExchange.Create(new Contact { ChatAddress = storedContactAddress }, keyPair.PublicKey, keyPair.PublicKey).Payload);

      var requestBundle = CreateBundle(
        contactRequestAddress,
        ContactExchange.Create(
          new Contact { ChatAddress = storedContactAddress, Request = true, Name = "Requester" },
          keyPair.PublicKey,
          keyPair.PublicKey).Payload);

      var messenger = new InMemoryMessenger();

      messenger.SentMessages.Add(new Message(rejectedContactBundle.Transactions.Aggregate(new TryteString(), (current, transaction) => current.Concat(transaction.Fragment)), contactRequestAddress));
      messenger.SentMessages.Add(new Message(approvedContactBundle.Transactions.Aggregate(new TryteString(), (current, transaction) => current.Concat(transaction.Fragment)), contactRequestAddress));
      messenger.SentMessages.Add(new Message(requestBundle.Transactions.Aggregate(new TryteString(), (current, transaction) => current.Concat(transaction.Fragment)), contactRequestAddress));

      var interactor = new GetContactsInteractor(contactRepository, messenger, NtruEncryption.Key);
      var response = await interactor.ExecuteAsync(
                       new GetContactsRequest
                         {
                           PublicKeyAddress = new Address(pubKeyAddress),
                           RequestAddress = contactRequestAddress,
                           KeyPair = keyPair
                       });

      Assert.AreEqual(ResponseCode.Success, response.Code);
      Assert.AreEqual(1, response.ApprovedContacts.Count);
      Assert.AreEqual(1, response.PendingContactRequests.Count);
    }

    private static Bundle CreateBundle(Address address, TryteString message)
    {
      var bundle = new Bundle();
      bundle.AddTransfer(
        new Transfer
          {
            Address = address,
            Message = message,
            Timestamp = Timestamp.UnixSecondsTimestamp,
            Tag = Constants.Tag
          });

      bundle.Finalize();
      bundle.Sign();

      // calculate hashes
      var transactions = bundle.Transactions;
      bundle.Transactions = transactions.Select(t => Transaction.FromTrytes(t.ToTrytes())).ToList();
      return bundle;
    }

    [TestMethod]
    public async Task TestExceptionGetsThrownShouldReturnErrorCode()
    {
      var interactor = new GetContactsInteractor(new ExceptionContactRepository(), new InMemoryMessenger(), new EncryptionStub());
      var response = await interactor.ExecuteAsync(new GetContactsRequest { PublicKeyAddress = new Address(Hash.Empty.Value) });

      Assert.AreEqual(ResponseCode.ContactsUnavailable, response.Code);
    }
  }
}