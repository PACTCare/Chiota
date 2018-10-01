namespace Chiota.Messenger.Repository
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Extensions;
  using Chiota.Messenger.Usecase;

  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;
  using Tangle.Net.Repository;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  public abstract class AbstractTangleContactRepository : IContactRepository
  {
    public AbstractTangleContactRepository(IIotaRepository iotaRepository, ISignatureValidator signatureValidator)
    {
      this.IotaRepository = iotaRepository;
      this.SignatureValidator = signatureValidator;
    }

    private IIotaRepository IotaRepository { get; }

    private ISignatureValidator SignatureValidator { get; }

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

      var latestContactInformation = await this.LoadRawContactInformationFromTangle(transactionHashesOnAddress.Hashes, address);
      if (latestContactInformation == null)
      {
        throw new MessengerException(ResponseCode.NoContactInformationPresent);
      }

      return ExtractContactInformation(latestContactInformation);
    }

    /// <inheritdoc />
    public abstract Task<List<Contact>> LoadContactsAsync(string publicKeyAddress);

    private static ContactInformation ExtractContactInformation(TryteString latestContactInformation)
    {
      var lineBreakIndex = latestContactInformation.Value.IndexOf(Constants.LineBreak.Value, StringComparison.Ordinal);
      var publicKeyString = latestContactInformation.Value.Substring(0, lineBreakIndex);
      var bytesKey = new TryteString(publicKeyString).DecodeBytesFromTryteString();

      return new ContactInformation
               {
                 NtruKey = new NTRUPublicKey(bytesKey),
                 ContactAddress = new Address(
                   latestContactInformation.Value.Substring(lineBreakIndex + Constants.LineBreak.Value.Length, Address.Length))
               };
    }

    private async Task<TryteString> LoadRawContactInformationFromTangle(List<Hash> transactionHashes, Address address)
    {
      foreach (var bundle in await this.LoadTransactionBundlesAsync(transactionHashes))
      {
        try
        {
          var bundleTrytes = bundle.Transactions.OrderBy(t => t.CurrentIndex).Aggregate(
            new TryteString(),
            (current, tryteString) => current.Concat(tryteString.Fragment));

          if (!bundleTrytes.Value.Contains(Constants.End.Value) || !bundleTrytes.Value.Contains(Constants.LineBreak.Value))
          {
            continue;
          }

          var contactPayloadEnd = bundleTrytes.Value.IndexOf(Constants.End.Value, StringComparison.Ordinal);
          if (this.ValidateSignature(address, bundleTrytes, contactPayloadEnd))
          {
            return new TryteString(bundleTrytes.Value.Substring(0, contactPayloadEnd));
          }
        }
        catch
        {
          // ignored, since invalid transactions on the address will lead us here
        }
      }

      return null;
    }

    private async Task<List<Bundle>> LoadTransactionBundlesAsync(List<Hash> transactionHashes)
    {
      var transactions = (await this.IotaRepository.GetTrytesAsync(transactionHashes)).Select(t => Transaction.FromTrytes(t)).ToList();
      var bundles = new List<Bundle>();

      foreach (var transaction in transactions)
      {
        var bundle = bundles.FirstOrDefault(b => b.Hash.Value == transaction.BundleHash.Value);
        if (bundle != null)
        {
          bundle.Transactions.Add(transaction);
        }
        else
        {
          bundle = new Bundle();
          bundle.Transactions.Add(transaction);
          bundles.Add(bundle);
        }
      }

      return bundles;
    }

    private bool ValidateSignature(Address address, TryteString bundleTrytes, int contactPayloadEnd)
    {
      var signatureLength = Constants.MessengerSecurityLevel * Fragment.Length;
      var signature = bundleTrytes.GetChunk(contactPayloadEnd + Constants.End.TrytesLength, signatureLength);

      return this.SignatureValidator.ValidateFragments(
        signature.GetChunks(Fragment.Length).Select(c => new Fragment(c.Value)).ToList(),
        new Hash(address.DeriveRequestAddress().Value),
        address);
    }
  }
}