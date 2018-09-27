namespace Chiota.Messenger.Tests.Usecase
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Tests.Encryption;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Tests.Service;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.GetMessages;
  using Chiota.Messenger.Usecase.SendMessage;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

  [TestClass]
  public class GetMessagesInteractorTest
  {
    [TestMethod]
    public async Task TestMessengerThrowExceptionShouldReturnErrorCode()
    {
      var interactor = new GetMessagesInteractor(new ExceptionMessenger(), new EncryptionStub());
      var result = await interactor.ExecuteAsync(
        new GetMessagesRequest
          {
            ChatAddress = new Address(Hash.Empty.Value),
            ChatKeyPair = InMemoryContactRepository.NtruKeyPair
          });

      Assert.AreEqual(ResponseCode.MessengerException, result.Code);
    }

    [TestMethod]
    public async Task TestInvalidMessagesShouldBeIgnored()
    {
      var messenger = new InMemoryMessenger();
      messenger.SentMessages.Add(new Message(new TryteString("GHAFSGHAFSGHFASAAS"), new Address(Hash.Empty.Value)));

      var interactor = new GetMessagesInteractor(messenger, new EncryptionStub());
      var result = await interactor.ExecuteAsync(
                     new GetMessagesRequest
                       {
                         ChatAddress = new Address(Hash.Empty.Value),
                         ChatKeyPair = InMemoryContactRepository.NtruKeyPair
                       });

      Assert.AreEqual(ResponseCode.Success, result.Code);
    }

    [TestMethod]
    public async Task TestValidMessageCanBeParsedCorrectly()
    {
      // TODO: extract crypto class
    }
  }
}