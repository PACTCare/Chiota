namespace Chiota.Messenger.Tests.Usecase
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Comparison;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Usecase.GetApprovedContacts;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

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
      var interactor = new GetApprovedContactsInteractor(new InMemoryContactRepository());
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

      var interactor = new GetApprovedContactsInteractor(contactRepository);
      var response = await interactor.ExecuteAsync(new GetApprovedContactsRequest { PublicKeyAddress = new Address(pubKeyAddress) });

      Assert.AreEqual(2, response.Contacts.Count);
    }
  }
}