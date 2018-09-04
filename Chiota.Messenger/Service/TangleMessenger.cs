namespace Chiota.Messenger.Service
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
  using Tangle.Net.Utils;

  using Constants = Chiota.Messenger.Constants;

  /// <inheritdoc />
  /// <summary>
  /// The tangle messenger.
  /// </summary>
  public class TangleMessenger : IMessenger
  {
    public TangleMessenger(IIotaRepository repository)
    {
      this.Repository = repository;
    }

    private IIotaRepository Repository { get; }

    /// <inheritdoc />
    public async Task<List<Message>> GetMessagesByAddressAsync(Address address)
    {
      var result = new List<Message>();
      var transactionHashes = await this.Repository.FindTransactionsByAddressesAsync(new List<Address> { address });

      foreach (var transactionHash in transactionHashes.Hashes)
      {
        var bundle = await this.Repository.GetBundleAsync(transactionHash);
        result.Add(new Message(MessageType.RequestContact, ExtractMessage(bundle), address));
      }

      return result;
    }

    /// <inheritdoc />
    public async Task SendMessageAsync(Message message)
    {
      if (!message.HasKnownType)
      {
        throw new MessengerException(ResponseCode.MessengerException, new UnknownMessageException(message.Type));
      }

      try
      {
        var bundle = new Bundle();
        bundle.AddTransfer(
          new Transfer
            {
              Address = message.Receiver,
              Message = message.Payload,
              Tag = Constants.Tag,
              Timestamp = Timestamp.UnixSecondsTimestamp
            });

        bundle.Finalize();
        bundle.Sign();

        await this.Repository.SendTrytesAsync(bundle.Transactions);
      }
      catch (Exception exception)
      {
        throw new MessengerException(ResponseCode.MessengerException, exception);
      }
    }

    private static TryteString ExtractMessage(Bundle bundle)
    {
      var messageTrytes = string.Empty;

      // multiple message per bundle?
      foreach (var transaction in bundle.Transactions)
      {
        if (transaction.Value < 0)
        {
          continue;
        }

        if (!transaction.Fragment.IsEmpty)
        {
          messageTrytes += transaction.Fragment.Value;
        }
      }

      if (!messageTrytes.Contains(Constants.End))
      {
        return null;
      }

      var index = messageTrytes.IndexOf(Constants.End, StringComparison.Ordinal);
      return new TryteString(messageTrytes.Substring(0, index));
    }
  }
}