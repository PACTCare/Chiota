namespace Chiota.Messenger.Tests.Usecase
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Tests.Encryption;
  using Chiota.Messenger.Tests.Service;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.CreateUser;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

  [TestClass]
  public class CreateUserInteractorTest
  {
    [DataTestMethod]
    [DataRow(typeof(Exception), ResponseCode.UnkownException)]
    [DataRow(typeof(MessengerException), ResponseCode.MessengerException)]
    public async Task TestExceptionIsThrownShouldReturnErrorCode(Type exceptionType, ResponseCode code)
    {
      var exception = exceptionType == typeof(MessengerException) ? new MessengerException(code) : new Exception();

      var interactor = new CreateUserInteractor(
        new ExceptionMessenger(exception),
        new InMemoryAddressGenerator(),
        new EncryptionStub(),
        new SignatureGeneratorStub());
      var response = await interactor.ExecuteAsync(new CreateUserRequest { Seed = Seed.Random() });

      Assert.AreEqual(code, response.Code);
    }

    [TestMethod]
    public async Task TestCreatedUserDataIsSentSignedAndReturned()
    {
      var seed = Seed.Random();
      var inMemoryMessenger = new InMemoryMessenger();
      var interactor = new CreateUserInteractor(
        inMemoryMessenger,
        new InMemoryAddressGenerator(),
        new EncryptionStub(),
        new SignatureGeneratorStub());
      var response = await interactor.ExecuteAsync(new CreateUserRequest { Seed = seed });

      Assert.AreEqual(ResponseCode.Success, response.Code);
      Assert.AreEqual(seed.Value, response.PublicKeyAddress.Value);
      Assert.IsNotNull(response.RequestAddress);
      Assert.IsNotNull(response.NtruKeyPair);
      Assert.IsTrue(inMemoryMessenger.SentMessages[0].Payload.Value.Contains("STUBFRAGMENTSIGNATURE"));
    }
  }
}