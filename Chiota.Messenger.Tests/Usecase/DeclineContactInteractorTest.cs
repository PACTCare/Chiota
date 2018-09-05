namespace Chiota.Messenger.Tests.Usecase
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.DeclineContact;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

  /// <summary>
  /// The decline contact interactor test.
  /// </summary>
  [TestClass]
  public class DeclineContactInteractorTest
  {
    /// <summary>
    /// The test contact repository throws exception should return error code.
    /// </summary>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    [TestMethod]
    public async Task TestContactRepositoryThrowsExceptionShouldReturnErrorCode()
    {
      var interactor = new DeclineContactInteractor(new ExceptionContactRepository());
      var response = await interactor.ExecuteAsync(
                       new DeclineContactRequest
                         {
                           ContactChatAddress = new Address(Hash.Empty.Value), UserPublicKeyAddress = new Address(Hash.Empty.Value)
                         });

      Assert.AreEqual(ResponseCode.UnkownException, response.Code);
    }

    [TestMethod]
    public async Task TestDeclinedContactGetsAddedToRepository()
    {
      var contactRepository = new InMemoryContactRepository();
      var interactor = new DeclineContactInteractor(contactRepository);
      var response = await interactor.ExecuteAsync(
                       new DeclineContactRequest
                         {
                           ContactChatAddress = new Address(Hash.Empty.Value),
                           UserPublicKeyAddress = new Address(Hash.Empty.Value)
                         });

      Assert.AreEqual(ResponseCode.Success, response.Code);

      Assert.AreEqual(Hash.Empty.Value, contactRepository.PersistedContacts[0].ChatAddress);
      Assert.AreEqual(Hash.Empty.Value, contactRepository.PersistedContacts[0].PublicKeyAddress);
      Assert.IsTrue(contactRepository.PersistedContacts[0].Rejected);
    }
  }
}