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
  public abstract class AbstractTangleContactRepository : IContactRepository
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="AbstractTangleContactRepository"/> class.
    /// </summary>
    /// <param name="iotaRepository">
    /// The iota repository.
    /// </param>
    public AbstractTangleContactRepository(IIotaRepository iotaRepository)
    {
      this.IotaRepository = iotaRepository;
    }

    /// <summary>
    /// Gets the iota repository.
    /// </summary>
    private IIotaRepository IotaRepository { get; }

    /// <inheritdoc />
    public abstract Task AddContactAsync(string address, bool accepted, string publicKeyAddress);

    /// <inheritdoc />
    public async Task<ContactInformation> LoadContactInformationByAddressAsync(Address address)
    {
      var transactionHashesOnAddress = await this.IotaRepository.FindTransactionsByAddressesAsync(new List<Address> { address });
      if (transactionHashesOnAddress.Hashes.Count == 0)
      {
        throw new MessengerException(ResponseCode.NoContactInformationPresent);
      }

      var latestContactInformation = await this.LoadRawContactInformationFromTangle(transactionHashesOnAddress.Hashes);
      if (latestContactInformation == null)
      {
        throw new MessengerException(ResponseCode.NoContactInformationPresent);
      }

      return ExtractContactInformation(latestContactInformation);
    }

    /// <inheritdoc />
    public abstract Task<List<Contact>> LoadContactsAsync(string publicKeyAddress);

    /// <summary>
    /// The extract contact information.
    /// </summary>
    /// <param name="latestContactInformation">
    /// The latest contact information.
    /// </param>
    /// <returns>
    /// The <see cref="ContactInformation"/>.
    /// </returns>
    private static ContactInformation ExtractContactInformation(TryteString latestContactInformation)
    {
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

    /// <summary>
    /// The load contact information from tangle.
    /// </summary>
    /// <param name="transactionHashes">
    /// The transaction hashes on address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task<TryteString> LoadRawContactInformationFromTangle(IEnumerable<Hash> transactionHashes)
    {
      TryteString latestContactInformation = null;
      foreach (var transactionHash in transactionHashes)
      {
        var contactInformationBundle = await this.IotaRepository.GetBundleAsync(transactionHash);
        var bundleTrytes = contactInformationBundle.Transactions.Aggregate(
          new TryteString(),
          (current, tryteString) => current.Concat(tryteString.Fragment));

        if (!bundleTrytes.Value.Contains(Constants.End) || !bundleTrytes.Value.Contains(Constants.LineBreak))
        {
          continue;
        }

        if (latestContactInformation == null)
        {
          latestContactInformation =
            new TryteString(bundleTrytes.Value.Substring(0, bundleTrytes.Value.IndexOf(Constants.End, StringComparison.Ordinal)));
        }
        else
        {
          throw new MessengerException(ResponseCode.AmbiguousContactInformation);
        }
      }

      return latestContactInformation;
    }
  }
}