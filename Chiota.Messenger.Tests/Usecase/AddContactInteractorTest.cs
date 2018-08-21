namespace Chiota.Messenger.Tests.Usecase
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Tests.Service;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AddContact;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The add contact interactor test.
  /// </summary>
  [TestClass]
  public class AddContactInteractorTest
  {
    [TestMethod]
    public async Task TestContactCanNotBeAddedToContactRepositoryShouldReturnErrorCode()
    {
      var respository = new ExceptionContactRepository();
      var interactor = new AddContactInteractor(respository, new InMemoryMessenger());
      var request = new AddContactRequest { ContactAddress = new Address(), NtruKey = this.NtruKeyPair.PublicKey };

      var response = await interactor.ExecuteAsync(request);

      Assert.AreEqual(ResponseCode.CannotAddContact, response.Code);
    }

    [TestMethod]
    public async Task TestGivenContactIsStoredInGivenRepository()
    {
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(respository, new InMemoryMessenger());
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var request = new AddContactRequest { ContactAddress = contactAddress, NtruKey = this.NtruKeyPair.PublicKey };

      await interactor.ExecuteAsync(request);

      Assert.AreEqual(1, respository.PersistedContacts.Count);
      Assert.AreEqual(contactAddress.Value, respository.PersistedContacts[0].ContactAddress);
    }

    [TestMethod]
    public async Task TestMessengerCannotSendMessageShouldReturnErrorCodeAndNotWriteToContactRepository()
    {
      var messenger = new ExceptionMessenger();
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(respository, messenger);
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var request = new AddContactRequest { ContactAddress = contactAddress };

      var response = await interactor.ExecuteAsync(request);

      Assert.AreEqual(ResponseCode.MessengerException, response.Code);
      Assert.AreEqual(0, respository.PersistedContacts.Count);
    }

    [TestMethod]
    public async Task TestMessengerGetsCalledWithAddContactRequestAndContactJsonPayload()
    {
      var messenger = new InMemoryMessenger();
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(respository, messenger);
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var request = new AddContactRequest { ContactAddress = contactAddress, NtruKey = this.NtruKeyPair.PublicKey };

      await interactor.ExecuteAsync(request);

      Assert.AreEqual(2, messenger.SentMessages.Count);

      var sentMessage = messenger.SentMessages[0];
      Assert.AreEqual(contactAddress.Value, sentMessage.Receiver.Value);

      var sentPayload = JsonConvert.DeserializeObject<Contact>(sentMessage.Payload.ToUtf8String());

      Assert.AreEqual(contactAddress.Value, sentPayload.ContactAddress);
    }

    [TestMethod]
    public async Task TestChatPasKeyIsSentViaMessenger()
    {
      var messenger = new InMemoryMessenger();
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(respository, messenger);
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var request = new AddContactRequest { ContactAddress = contactAddress, NtruKey = this.NtruKeyPair.PublicKey };

      var response = await interactor.ExecuteAsync(request);

      Assert.AreEqual(2, messenger.SentMessages.Count);
      Assert.AreEqual(ResponseCode.Success, response.Code);
    }

    private IAsymmetricKeyPair NtruKeyPair =>
      new NtruKeyExchange(NTRUParamSets.NTRUParamNames.A2011743).CreateAsymmetricKeyPair(
        Seed.Random().Value.ToLower(),
        Seed.Random().Value.ToLower());
  }
}