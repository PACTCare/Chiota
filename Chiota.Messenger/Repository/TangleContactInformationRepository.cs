namespace Chiota.Messenger.Repository
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Usecase;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  /// <summary>
  /// The tangle contact information repository.
  /// </summary>
  public class TangleContactInformationRepository : IContactInformationRepository
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="TangleContactInformationRepository"/> class.
    /// </summary>
    /// <param name="iotaRepository">
    /// The iota repository.
    /// </param>
    public TangleContactInformationRepository(IIotaRepository iotaRepository)
    {
      this.IotaRepository = iotaRepository;
    }

    /// <summary>
    /// Gets the iota repository.
    /// </summary>
    private IIotaRepository IotaRepository { get; }

    /// <inheritdoc />
    public async Task<ContactInformation> LoadContactInformationByAddressAsync(Address address)
    {
      var transactionHashesOnAddress = await this.IotaRepository.FindTransactionsByAddressesAsync(new List<Address> { address });

      if (transactionHashesOnAddress.Hashes.Count == 0)
      {
        throw new MessengerException(ResponseCode.NoContactInformationPresent);
      }

      var latestContactInformation = new TryteString();

      foreach (var transactionHash in transactionHashesOnAddress.Hashes)
      {
        var contactInformationBundle = await this.IotaRepository.GetBundleAsync(transactionHash);
        var bundleTrytes = contactInformationBundle.Transactions.Aggregate(
          new TryteString(),
          (current, tryteString) => current.Concat(tryteString.Fragment));

        if (!bundleTrytes.Value.Contains(Constants.End) || !bundleTrytes.Value.Contains(Constants.LineBreak))
        {
          continue;
        }

        latestContactInformation =
          new TryteString(bundleTrytes.Value.Substring(0, bundleTrytes.Value.IndexOf(Constants.End, StringComparison.Ordinal)));

        break;
      }

      var lineBreakIndex = latestContactInformation.Value.IndexOf(Constants.LineBreak, StringComparison.Ordinal);
      var publicKeyString = latestContactInformation.Value.Substring(0, lineBreakIndex);
      var bytesKey = new TryteString(publicKeyString).DecodeBytesFromTryteString();

      return new ContactInformation
               {
                 NtruKey = new NTRUPublicKey(bytesKey),
                 ContactAddress = new Address(
                   latestContactInformation.Value.Substring(lineBreakIndex + Constants.LineBreak.Length, Address.Length))
               };
    }
  }
}