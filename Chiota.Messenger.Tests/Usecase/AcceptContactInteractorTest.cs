namespace Chiota.Messenger.Tests.Usecase
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Tests.Encryption;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Tests.Service;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AcceptContact;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

  /// <summary>
  /// The accept contact interactor test.
  /// </summary>
  [TestClass]
  public class AcceptContactInteractorTest
  {
    [TestMethod]
    public async Task TestChatPasCannotBeCreatedShouldReturnErrorCode()
    {
      var interactor = new AcceptContactInteractor(new InMemoryContactRepository(), new InMemoryMessenger(), new EncryptionStub());
      var response = await interactor.ExecuteAsync(new AcceptContactRequest
                                                     {
                                                       ChatKeyAddress = new Address(Hash.Empty.Value),
                                                       ChatAddress = new Address(Hash.Empty.Value),
                                                       ContactPublicKeyAddress = new Address(Hash.Empty.Value),
                                                       ContactAddress = new Address(Hash.Empty.Value),
                                                       UserImagePath = string.Empty,
                                                       UserPublicKeyAddress = new Address(Hash.Empty.Value),
                                                       UserName = string.Empty,
                                                       UserKeyPair = InMemoryContactRepository.NtruKeyPair,
                                                       UserContactAddress = new Address(Hash.Empty.Value)
      });

      Assert.AreEqual(ResponseCode.ChatPasswordAndSaltCannotBeGenerated, response.Code);
    }

    [TestMethod]
    public async Task TestChatPasCanBeCreatedShouldPersistContactAndSendInformation()
    {
      Assert.Inconclusive("TODO: To be tested the crypto module needs to be separated from interactor.");
      var inMemoryMessenger = new InMemoryMessenger();

      inMemoryMessenger.SentMessages.Add(new Message(new TryteString(""), new Address(Hash.Empty.Value)));

      var interactor = new AcceptContactInteractor(new InMemoryContactRepository(), inMemoryMessenger, new EncryptionStub());
      var response = await interactor.ExecuteAsync(new AcceptContactRequest
                                                     {
                                                       ChatKeyAddress = new Address(Hash.Empty.Value),
                                                       ChatAddress = new Address(Hash.Empty.Value),
                                                       ContactPublicKeyAddress = new Address(Hash.Empty.Value),
                                                       ContactAddress = new Address(Hash.Empty.Value),
                                                       UserImagePath = string.Empty,
                                                       UserPublicKeyAddress = new Address(Hash.Empty.Value),
                                                       UserName = string.Empty,
                                                       UserKeyPair = InMemoryContactRepository.NtruKeyPair
                                                     });

      Assert.AreEqual(ResponseCode.Success, response.Code);
    }
  }
}