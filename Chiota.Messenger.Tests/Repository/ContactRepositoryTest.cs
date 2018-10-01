namespace Chiota.Messenger.Tests.Repository
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Extensions;
  using Chiota.Messenger.Tests.Service;
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

        var repository = new ContactRepositoryStub(iotaRepository.Object, new SignatureValidatorStub());
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

        iotaRepository.Setup(r => r.GetTrytesAsync(It.IsAny<List<Hash>>())).ReturnsAsync(
          new List<TransactionTrytes> { invalidBundleOne.Transactions[0].ToTrytes(), invalidBundleTwo.Transactions[0].ToTrytes() });

        var repository = new ContactRepositoryStub(iotaRepository.Object, new SignatureValidatorStub(false));
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

      var iotaRepository = new Mock<IIotaRepository>();
      iotaRepository.Setup(r => r.FindTransactionsByAddressesAsync(It.IsAny<IEnumerable<Address>>())).ReturnsAsync(
        new TransactionHashList { Hashes = new List<Hash> { invalidBundle.Hash, validBundle.Hash } });

      var transactionTrytes = invalidBundle.ToTrytes();
      transactionTrytes.AddRange(validBundle.ToTrytes());
      iotaRepository.Setup(r => r.GetTrytesAsync(It.IsAny<List<Hash>>())).ReturnsAsync(transactionTrytes);

      var repository = new ContactRepositoryStub(iotaRepository.Object, new SignatureValidatorStub());
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