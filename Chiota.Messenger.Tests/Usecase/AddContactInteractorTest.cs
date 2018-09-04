namespace Chiota.Messenger.Tests.Usecase
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Tests.Service;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AddContact;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Moq;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

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
      var request = new AddContactRequest
                      {
                        ContactAddress = new Address(),
                        RequestAddress = new Address(Seed.Random().Value),
                        ImageHash = "kjasdjkahsda89dafhfafa",
                        Name = "Chiota User",
                        PublicKeyAddress = new Address(Seed.Random().Value)
                      };

      var response = await interactor.ExecuteAsync(request);

      Assert.AreEqual(ResponseCode.CannotAddContact, response.Code);
    }

    [TestMethod]
    public async Task TestGivenContactIsStoredInGivenRepository()
    {
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(respository, new InMemoryMessenger());
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var publicKeyAddress = Seed.Random().Value;
      var request = new AddContactRequest
                      {
                        ContactAddress = contactAddress,
                        RequestAddress = new Address(Seed.Random().Value),
                        ImageHash = "kjasdjkahsda89dafhfafa",
                        Name = "Chiota User",
                        PublicKeyAddress = new Address(publicKeyAddress)
                      };

      await interactor.ExecuteAsync(request);

      Assert.AreEqual(1, respository.PersistedContacts.Count);

      var contact = respository.PersistedContacts[0];
      Assert.AreEqual(publicKeyAddress, contact.PublicKeyAddress);
      Assert.IsFalse(contact.Rejected);
      Assert.IsNotNull(contact.ChatAddress);

    }

    [TestMethod]
    public async Task TestMessengerCannotSendMessageShouldReturnErrorCodeAndNotWriteToContactRepository()
    {
      var messenger = new ExceptionMessenger();
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(respository, messenger);
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var request = new AddContactRequest
                      {
                        ContactAddress = contactAddress,
                        RequestAddress = new Address(Seed.Random().Value),
                        ImageHash = "kjasdjkahsda89dafhfafa",
                        Name = "Chiota User",
                        PublicKeyAddress = new Address(Seed.Random().Value)
                      };

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
      var requestAddress = Seed.Random().Value;
      var publicKeyAddress = Seed.Random().Value;

      var request = new AddContactRequest
                      {
                        ContactAddress = contactAddress,
                        RequestAddress = new Address(requestAddress),
                        ImageHash = "kjasdjkahsda89dafhfafa",
                        Name = "Chiota User",
                        PublicKeyAddress = new Address(publicKeyAddress)
                      };

      await interactor.ExecuteAsync(request);

      Assert.AreEqual(2, messenger.SentMessages.Count);

      var sentMessage = messenger.SentMessages[0];
      Assert.AreEqual(contactAddress.Value, sentMessage.Receiver.Value);

      var utf8String = sentMessage.Payload.ToUtf8String();
      var sentPayload = JsonConvert.DeserializeObject<Contact>(utf8String);

      Assert.AreEqual("kjasdjkahsda89dafhfafa", sentPayload.ImageHash);
      Assert.AreEqual("Chiota User", sentPayload.Name);
      Assert.AreEqual(publicKeyAddress, sentPayload.PublicKeyAddress);
      Assert.AreEqual(requestAddress, sentPayload.ContactAddress);
      Assert.IsTrue(InputValidator.IsAddress(sentPayload.ChatAddress));
      Assert.IsTrue(InputValidator.IsAddress(sentPayload.ChatKeyAddress));
      Assert.IsTrue(sentPayload.Request);
      Assert.IsFalse(sentPayload.Rejected);
    }

    [TestMethod]
    public async Task TestChatPasKeyIsSentViaMessenger()
    {
      var messenger = new InMemoryMessenger();
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(respository, messenger);
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var request = new AddContactRequest
                      {
                        ContactAddress = contactAddress,
                        RequestAddress = new Address(Seed.Random().Value),
                        ImageHash = "kjasdjkahsda89dafhfafa",
                        Name = "Chiota User",
                        PublicKeyAddress = new Address(Seed.Random().Value)
                      };

      var response = await interactor.ExecuteAsync(request);

      Assert.AreEqual(2, messenger.SentMessages.Count);
      Assert.AreEqual(ResponseCode.Success, response.Code);
    }

    [TestMethod]
    public async Task TestNoContactInformationCanBeFoundShouldReturnErrorCode()
    {
      var contactRepositoryMock = new Mock<IContactRepository>();
      contactRepositoryMock.Setup(c => c.LoadContactInformationByAddressAsync(It.IsAny<Address>()))
        .Throws(new MessengerException(ResponseCode.NoContactInformationPresent));

      var messenger = new InMemoryMessenger();
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(contactRepositoryMock.Object, messenger);
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var request = new AddContactRequest
                      {
                        ContactAddress = contactAddress,
                        RequestAddress = new Address(Seed.Random().Value),
                        ImageHash = "kjasdjkahsda89dafhfafa",
                        Name = "Chiota User",
                        PublicKeyAddress = new Address(Seed.Random().Value)
                      };

      var response = await interactor.ExecuteAsync(request);

      Assert.AreEqual(ResponseCode.NoContactInformationPresent, response.Code);
    }

    [TestMethod]
    public async Task TestUnkownExceptionIsThrownShouldReturnErrorCode()
    {
      var messenger = new ExceptionMessenger(new Exception("Hi"));
      var respository = new InMemoryContactRepository();
      var interactor = new AddContactInteractor(respository, messenger);
      var contactAddress = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var request = new AddContactRequest
                      {
                        ContactAddress = contactAddress,
                        RequestAddress = new Address(Seed.Random().Value),
                        ImageHash = "kjasdjkahsda89dafhfafa",
                        Name = "Chiota User",
                        PublicKeyAddress = new Address(Seed.Random().Value)
                      };

      var response = await interactor.ExecuteAsync(request);

      Assert.AreEqual(ResponseCode.UnkownException, response.Code);
    }
  }
}