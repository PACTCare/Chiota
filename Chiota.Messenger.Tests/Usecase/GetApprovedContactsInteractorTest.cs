namespace Chiota.Messenger.Tests.Usecase
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Comparison;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Tests.Cache;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Usecase.GetApprovedContacts;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Moq;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.DataTransfer;

  /// <summary>
  /// The get approved contacts interactor test.
  /// </summary>
  [TestClass]
  public class GetApprovedContactsInteractorTest
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
      var interactor = new GetApprovedContactsInteractor(new InMemoryContactRepository(), new InMemoryTransactionCache(), new InMemoryIotaRepository());
      var response = await interactor.ExecuteAsync(new GetApprovedContactsRequest { PublicKeyAddress = new Address(Hash.Empty.Value) });

      Assert.AreEqual(0, response.Contacts.Count);
    }

    [TestMethod]
    public async Task TestOnlyContactRepositoryContainsContactsShouldReturnOnlyThem()
    {
      var contactRepository = new InMemoryContactRepository();

      var pubKeyAddress = Seed.Random().Value;
      await contactRepository.AddContactAsync(Seed.Random().Value, true, pubKeyAddress);
      await contactRepository.AddContactAsync(Seed.Random().Value, true, pubKeyAddress);

      var interactor = new GetApprovedContactsInteractor(contactRepository, new InMemoryTransactionCache(), new InMemoryIotaRepository());
      var response = await interactor.ExecuteAsync(new GetApprovedContactsRequest { PublicKeyAddress = new Address(pubKeyAddress) });

      Assert.AreEqual(2, response.Contacts.Count);
    }

    [TestMethod]
    public async Task TestContactsAreContainedOnTangleAndLocallyShouldReturnBoth()
    {
      var pubKeyAddress = Seed.Random().Value;
      var contactRequestAddress = new Address(Seed.Random().Value);

      var contactRepository = new InMemoryContactRepository();
      var transactionCache = new InMemoryTransactionCache();

      var cacheItem = new TransactionCacheItem
                                   {
                                     Address = contactRequestAddress,
                                     TransactionHash = new Hash(Seed.Random().Value),
                                     TransactionTrytes = TryteString.FromUtf8String(
                                       JsonConvert.SerializeObject(
                                         new Contact { ContactAddress = Seed.Random().Value }))
                                   };

      await transactionCache.SaveTransactionAsync(cacheItem);

      await contactRepository.AddContactAsync(Seed.Random().Value, true, pubKeyAddress);
      await contactRepository.AddContactAsync(Seed.Random().Value, true, pubKeyAddress);

      var iotaRepositoryMock = new Mock<IIotaRepository>();
      iotaRepositoryMock.Setup(i => i.FindTransactionsByAddressesAsync(It.IsAny<List<Address>>())).ReturnsAsync(
        new TransactionHashList { Hashes = new List<Hash> { cacheItem.TransactionHash } });

      var interactor = new GetApprovedContactsInteractor(contactRepository, transactionCache, iotaRepositoryMock.Object);
      var response = await interactor.ExecuteAsync(
                       new GetApprovedContactsRequest
                         {
                           PublicKeyAddress = new Address(pubKeyAddress),
                           ContactRequestAddress = contactRequestAddress
                         });

      Assert.AreEqual(3, response.Contacts.Count);
    }
  }
}