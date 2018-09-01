namespace Chiota.Messenger.Tests.Repository
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Usecase;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Moq;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.DataTransfer;

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
        var iotaRepository = new Mock<IIotaRepository>();
        iotaRepository.Setup(r => r.FindTransactionsByAddressesAsync(It.IsAny<IEnumerable<Address>>()))
          .ReturnsAsync(new TransactionHashList { Hashes = new List<Hash>() });

        var repository = new ContactRepositoryStub(iotaRepository.Object);
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

        var iotaRepository = new Mock<IIotaRepository>();
        iotaRepository.Setup(r => r.FindTransactionsByAddressesAsync(It.IsAny<IEnumerable<Address>>())).ReturnsAsync(
          new TransactionHashList { Hashes = new List<Hash> { invalidBundleOne.Hash, invalidBundleTwo.Hash } });

        iotaRepository.Setup(r => r.GetBundleAsync(It.Is<Hash>(h => h.Value == invalidBundleOne.Hash.Value))).ReturnsAsync(invalidBundleOne);
        iotaRepository.Setup(r => r.GetBundleAsync(It.Is<Hash>(h => h.Value == invalidBundleTwo.Hash.Value))).ReturnsAsync(invalidBundleTwo);

        var repository = new ContactRepositoryStub(iotaRepository.Object);
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
    public async Task TestAddressHasMoreThanOneValidTransactionShouldReturnErrorCode()
    {
      var exceptionThrown = false;
      try
      {
        var contactAddress = new Address(Seed.Random().Value);
        var ntruKey = InMemoryContactRepository.NtruKeyPair.PublicKey;
        var publicKeyTrytes = ntruKey.ToBytes().EncodeBytesAsString();
        var requestAdressTrytes = new TryteString(publicKeyTrytes + Constants.LineBreak + contactAddress.Value + Constants.End);

        var validBundleOne = CreateBundle(requestAdressTrytes);
        var validBundleTwo = CreateBundle(requestAdressTrytes);

        var iotaRepository = new Mock<IIotaRepository>();
        iotaRepository.Setup(r => r.FindTransactionsByAddressesAsync(It.IsAny<IEnumerable<Address>>())).ReturnsAsync(
          new TransactionHashList { Hashes = new List<Hash> { validBundleOne.Hash, validBundleTwo.Hash } });

        iotaRepository.Setup(r => r.GetBundleAsync(It.Is<Hash>(h => h.Value == validBundleOne.Hash.Value))).ReturnsAsync(validBundleOne);
        iotaRepository.Setup(r => r.GetBundleAsync(It.Is<Hash>(h => h.Value == validBundleTwo.Hash.Value))).ReturnsAsync(validBundleTwo);

        var repository = new ContactRepositoryStub(iotaRepository.Object);
        await repository.LoadContactInformationByAddressAsync(new Address());
      }
      catch (MessengerException exception)
      {
        exceptionThrown = true;
        Assert.AreEqual(ResponseCode.AmbiguousContactInformation, exception.Code);
      }

      Assert.IsTrue(exceptionThrown);
    }

    [TestMethod]
    public async Task TestAddressHasInvalidTransactionsShouldBeSkippedAndReturnValidData()
    {
      var contactAddress = new Address(Seed.Random().Value);
      var ntruKey = InMemoryContactRepository.NtruKeyPair.PublicKey;

      var publicKeyTrytes = ntruKey.ToBytes().EncodeBytesAsString();
      var requestAdressTrytes = new TryteString(publicKeyTrytes + Constants.LineBreak + contactAddress.Value + Constants.End);

      var invalidBundle = CreateBundle(new TryteString("999999999999999"));
      var validBundle = CreateBundle(requestAdressTrytes);

      var iotaRepository = new Mock<IIotaRepository>();
      iotaRepository.Setup(r => r.FindTransactionsByAddressesAsync(It.IsAny<IEnumerable<Address>>())).ReturnsAsync(
        new TransactionHashList { Hashes = new List<Hash> { invalidBundle.Hash, validBundle.Hash } });

      iotaRepository.SetupSequence(r => r.GetBundleAsync(It.IsAny<Hash>())).ReturnsAsync(invalidBundle).ReturnsAsync(validBundle);

      var repository = new ContactRepositoryStub(iotaRepository.Object);
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
            Address = new Address(Hash.Empty.Value),
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