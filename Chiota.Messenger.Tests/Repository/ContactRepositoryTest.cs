namespace Chiota.Messenger.Tests.Repository
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Extensions;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;
  using Chiota.Messenger.Tests.Service;
  using Chiota.Messenger.Usecase;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Moq;

  using Tangle.Net.Entity;

  using Timestamp = Tangle.Net.Utils.Timestamp;

  /// <summary>
  /// The tangle contact information repository test.
  /// </summary>
  [TestClass]
  public class ContactRepositoryTest
  {
    [TestMethod]
    public async Task TestAddressHasNoTransactionsShouldThrowExceptionWithErrorCode()
    {
      var exceptionThrown = false;
      try
      {
        var messenger = new Mock<IMessenger>();
        messenger.Setup(r => r.GetMessagesByAddressAsync(It.IsAny<Address>(), It.IsAny<IBundleParser>())).ReturnsAsync(new List<Message>());

        var repository = new ContactRepositoryStub(messenger.Object, new SignatureValidatorStub());
        await repository.LoadContactInformationByAddressAsync(new Address());
      }
      catch (MessengerException exception)
      {
        exceptionThrown = true;
        Assert.AreEqual(ResponseCode.NoContactInformationPresent, exception.Code);
      }

      Assert.IsTrue(exceptionThrown);
    }

    [TestMethod]
    public async Task TestAddressOnlyHasInvalidTransactionShouldReturnErrorCode()
    {
      var exceptionThrown = false;
      try
      {
        var invalidBundleOne = CreateBundle(new TryteString("999999999999999"));
        var invalidBundleTwo = CreateBundle(new TryteString("999999999999999"));

        var messenger = new Mock<IMessenger>();
        messenger.Setup(r => r.GetMessagesByAddressAsync(It.IsAny<Address>(), It.IsAny<IBundleParser>())).ReturnsAsync(
          new List<Message> { new Message(invalidBundleOne.Transactions[0].ToTrytes()), new Message(invalidBundleTwo.Transactions[0].ToTrytes()) });

        var repository = new ContactRepositoryStub(messenger.Object, new SignatureValidatorStub(false));
        await repository.LoadContactInformationByAddressAsync(new Address());
      }
      catch (MessengerException exception)
      {
        exceptionThrown = true;
        Assert.AreEqual(ResponseCode.NoContactInformationPresent, exception.Code);
      }

      Assert.IsTrue(exceptionThrown);
    }

    [TestMethod]
    public async Task TestAddressHasInvalidTransactionsShouldBeSkippedAndReturnValidData()
    {
      var contactAddress = new Address(Seed.Random().Value);
      var ntruKey = InMemoryContactRepository.NtruKeyPair.PublicKey;

      var publicKeyTrytes = ntruKey.ToBytes().EncodeBytesAsString();
      var requestAdressTrytes = new TryteString(publicKeyTrytes + Constants.LineBreak + contactAddress.Value + Constants.End).Concat(new Fragment())
        .Concat(new Fragment());

      var invalidBundle = CreateBundle(new TryteString("999999999999999"));
      var validBundle = CreateBundle(requestAdressTrytes);

      var messenger = new Mock<IMessenger>();
      messenger.Setup(r => r.GetMessagesByAddressAsync(It.IsAny<Address>(), It.IsAny<IBundleParser>())).ReturnsAsync(
        new List<Message>
          {
            new Message(invalidBundle.Transactions[0].ToTrytes()),
            new Message(validBundle.Transactions.Aggregate(new TryteString(), (current, tryteString) => current.Concat(tryteString.Fragment)))
          });

      var repository = new ContactRepositoryStub(messenger.Object, new SignatureValidatorStub());
      var contact = await repository.LoadContactInformationByAddressAsync(new Address());

      Assert.AreEqual(contactAddress.Value, contact.ContactAddress.Value);
      Assert.AreEqual(ntruKey.ToString(), contact.NtruKey.ToString());
    }

    private static Bundle CreateBundle(TryteString requestAdressTrytes)
    {
      var bundle = new Bundle();
      bundle.AddTransfer(
        new Transfer
          {
            Address = new Address(Seed.Random().Value),
            Message = requestAdressTrytes,
            Tag = Constants.Tag,
            Timestamp = Timestamp.UnixSecondsTimestamp
          });
      bundle.Finalize();
      bundle.Sign();

      return bundle;
    }
  }
}