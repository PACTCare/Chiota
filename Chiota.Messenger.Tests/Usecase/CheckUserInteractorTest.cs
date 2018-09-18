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
  using Chiota.Messenger.Usecase.CheckUser;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Moq;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  [TestClass]
  public class CheckUserInteractorTest
  {
    [DataTestMethod]
    [DataRow(typeof(Exception), ResponseCode.UnkownException)]
    [DataRow(typeof(MessengerException), ResponseCode.MessengerException)]
    public async Task TestExceptionIsHandledProperly(Type exceptionType, ResponseCode expectedCode)
    {
      var exception = exceptionType == typeof(MessengerException) ? new MessengerException(expectedCode) : new Exception();
      var interactor = new CheckUserInteractor(
        new ExceptionContactRepository(new MessengerException(ResponseCode.NoContactInformationPresent)),
        new ExceptionMessenger(exception),
        new InMemoryAddressGenerator());

      var response = await interactor.ExecuteAsync(
                       new CheckUserRequest
                         {
                           PublicKey = InMemoryContactRepository.NtruKeyPair.PublicKey,
                           PublicKeyAddress = new Address(Hash.Empty.Value),
                           RequestAddress = new Address(Hash.Empty.Value),
                           Seed = Seed.Random()
                         });

      Assert.AreEqual(expectedCode, response.Code);
    }

    [TestMethod]
    public async Task TestContactInformationDoesExistShouldReturnCodeSuccess()
    {
      var messenger = new InMemoryMessenger();
      var interactor = new CheckUserInteractor(new InMemoryContactRepository(), messenger, new InMemoryAddressGenerator());

      var response = await interactor.ExecuteAsync(
                       new CheckUserRequest
                         {
                           PublicKey = InMemoryContactRepository.NtruKeyPair.PublicKey,
                           PublicKeyAddress = new Address(Hash.Empty.Value),
                           RequestAddress = new Address(Hash.Empty.Value),
                           Seed = Seed.Random()
                         });

      Assert.AreEqual(ResponseCode.Success, response.Code);
      Assert.AreEqual(0, messenger.SentMessages.Count);
    }

    [TestMethod]
    public async Task TestContactInformationDoesNotExistAnymoreShouldResend()
    {
      var messenger = new InMemoryMessenger();
      var interactor = new CheckUserInteractor(
        new ExceptionContactRepository(new MessengerException(ResponseCode.NoContactInformationPresent)),
        messenger,
        new InMemoryAddressGenerator());

      var response = await interactor.ExecuteAsync(
                       new CheckUserRequest
                         {
                           PublicKey = InMemoryContactRepository.NtruKeyPair.PublicKey,
                           PublicKeyAddress = new Address(Hash.Empty.Value),
                           RequestAddress = new Address(Hash.Empty.Value),
                           Seed = Seed.Random()
                         });

      Assert.AreEqual(ResponseCode.Success, response.Code);
      Assert.AreEqual(1, messenger.SentMessages.Count);
    }

    [TestMethod]
    public async Task TestContactInformationIsAmbiguousShouldResendToNewPublicKeyAddress()
    {
      var contactRepositoryMock = new Mock<IContactRepository>();
      contactRepositoryMock.SetupSequence(r => r.LoadContactInformationByAddressAsync(It.IsAny<Address>()))
        .ThrowsAsync(new MessengerException(ResponseCode.AmbiguousContactInformation))
        .ThrowsAsync(new MessengerException(ResponseCode.NoContactInformationPresent));

      var messenger = new InMemoryMessenger();
      var interactor = new CheckUserInteractor(contactRepositoryMock.Object, messenger, new InMemoryAddressGenerator());

      var response = await interactor.ExecuteAsync(
                       new CheckUserRequest
                         {
                           PublicKey = InMemoryContactRepository.NtruKeyPair.PublicKey,
                           PublicKeyAddress = new Address(Hash.Empty.Value),
                           RequestAddress = new Address(Hash.Empty.Value),
                           Seed = Seed.Random()
                         });

      Assert.AreEqual(ResponseCode.NewPublicKeyAddress, response.Code);
      Assert.AreEqual(1, messenger.SentMessages.Count);
      Assert.IsNotNull(response.PublicKeyAddress);
    }

    [TestMethod]
    public async Task TestContactInformationIsFoundOnAnAlreadyAdjustedAddressShouldReturnCodeAndAdjustedAddress()
    {
      var contactRepositoryMock = new Mock<IContactRepository>();
      contactRepositoryMock.SetupSequence(r => r.LoadContactInformationByAddressAsync(It.IsAny<Address>()))
        .ThrowsAsync(new MessengerException(ResponseCode.AmbiguousContactInformation)).ReturnsAsync(
          new ContactInformation { ContactAddress = new Address(Hash.Empty.Value), NtruKey = InMemoryContactRepository.NtruKeyPair.PublicKey });

      var messenger = new InMemoryMessenger();
      var interactor = new CheckUserInteractor(contactRepositoryMock.Object, messenger, new InMemoryAddressGenerator());

      var response = await interactor.ExecuteAsync(
                       new CheckUserRequest
                         {
                           PublicKey = InMemoryContactRepository.NtruKeyPair.PublicKey,
                           PublicKeyAddress = new Address(Hash.Empty.Value),
                           RequestAddress = new Address(Hash.Empty.Value),
                           Seed = Seed.Random()
                         });

      Assert.AreEqual(ResponseCode.NewPublicKeyAddress, response.Code);
      Assert.AreEqual(0, messenger.SentMessages.Count);
      Assert.IsNotNull(response.PublicKeyAddress);
    }
  }
}