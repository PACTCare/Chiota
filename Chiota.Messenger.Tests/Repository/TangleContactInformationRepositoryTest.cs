namespace Chiota.Messenger.Tests.Repository
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Usecase;

  using Google.Protobuf.WellKnownTypes;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Moq;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.DataTransfer;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  using Timestamp = Tangle.Net.Utils.Timestamp;

  /// <summary>
  /// The tangle contact information repository test.
  /// </summary>
  [TestClass]
  public class TangleContactInformationRepositoryTest
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

        var repository = new TangleContactInformationRepository(iotaRepository.Object);
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
      var ntruKey = this.NtruKeyPair.PublicKey;

      var publicKeyTrytes = ntruKey.ToBytes().EncodeBytesAsString();
      var requestAdressTrytes = new TryteString(publicKeyTrytes + Constants.LineBreak + contactAddress.Value + Constants.End);

      var invalidBundle = CreateBundle(new TryteString("999999999999999"));
      var validBundle = CreateBundle(requestAdressTrytes);

      var iotaRepository = new Mock<IIotaRepository>();
      iotaRepository.Setup(r => r.FindTransactionsByAddressesAsync(It.IsAny<IEnumerable<Address>>())).ReturnsAsync(
        new TransactionHashList { Hashes = new List<Hash> { invalidBundle.Hash, validBundle.Hash } });

      iotaRepository.Setup(r => r.GetBundleAsync(It.Is<Hash>(h => h.Value == invalidBundle.Hash.Value))).ReturnsAsync(invalidBundle);
      iotaRepository.Setup(r => r.GetBundleAsync(It.Is<Hash>(h => h.Value == validBundle.Hash.Value))).ReturnsAsync(validBundle);

      var repository = new TangleContactInformationRepository(iotaRepository.Object);
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

    private IAsymmetricKeyPair NtruKeyPair =>
      new NtruKeyExchange(NTRUParamSets.NTRUParamNames.A2011743).CreateAsymmetricKeyPair(
        Seed.Random().Value.ToLower(),
        Seed.Random().Value.ToLower());
  }
}