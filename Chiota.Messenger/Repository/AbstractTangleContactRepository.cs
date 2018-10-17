namespace Chiota.Messenger.Repository
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Extensions;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Usecase;

  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  public abstract class AbstractTangleContactRepository : IContactRepository
  {
    public AbstractTangleContactRepository(IMessenger messenger, ISignatureValidator signatureValidator)
    {
      this.Messenger = messenger;
      this.SignatureValidator = signatureValidator;
    }

    private IMessenger Messenger { get; }

    private ISignatureValidator SignatureValidator { get; }

    /// <inheritdoc />
    public abstract Task AddContactAsync(string address, bool accepted, string publicKeyAddress);

    /// <inheritdoc />
    public async Task<ContactInformation> LoadContactInformationByAddressAsync(Address address)
    {
      var latestContactInformation = await this.LoadRawContactInformationFromTangle(address);
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
                 PublicKey = new NTRUPublicKey(bytesKey),
                 ContactAddress = new Address(
                   latestContactInformation.Value.Substring(lineBreakIndex + Constants.LineBreak.Value.Length, Address.Length))
               };
    }

    private async Task<TryteString> LoadRawContactInformationFromTangle(Address address)
    {
      foreach (var message in await this.Messenger.GetMessagesByAddressAsync(address))
      {
        try
        {
          if (!message.Payload.Value.Contains(Constants.End.Value) || !message.Payload.Value.Contains(Constants.LineBreak.Value))
          {
            continue;
          }

          var contactPayloadEnd = message.Payload.Value.IndexOf(Constants.End.Value, StringComparison.Ordinal);
          if (await this.ValidateSignatureAsync(address, message.Payload, contactPayloadEnd))
          {
            return new TryteString(message.Payload.Value.Substring(0, contactPayloadEnd));
          }
        }
        catch
        {
          // ignored, since invalid transactions on the address will lead us here
        }
      }

      return null;
    }

    private async Task<bool> ValidateSignatureAsync(Address address, TryteString bundleTrytes, int contactPayloadEnd)
    {
      var signatureLength = Constants.MessengerSecurityLevel * Fragment.Length;
      var signature = bundleTrytes.GetChunk(contactPayloadEnd + Constants.End.TrytesLength, signatureLength);
      var publicKeyPayload = new PublicKeyPayload(bundleTrytes.GetChunk(0, contactPayloadEnd + Constants.End.TrytesLength).Value);

      return await this.SignatureValidator.ValidateFragmentsAsync(
               signature.GetChunks(Fragment.Length).Select(c => new Fragment(c.Value)).ToList(),
               publicKeyPayload.Hash,
               address);
    }
  }
}