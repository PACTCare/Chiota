namespace Chiota.Messenger.Service
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service.Parser;
  using Chiota.Messenger.Usecase;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Utils;

  using Constants = Constants;

  /// <inheritdoc />
  /// <summary>
  /// The tangle messenger.
  /// </summary>
  public class TangleMessenger : IMessenger
  {
    public TangleMessenger(IIotaRepository repository, ITransactionCache transactionCache)
    {
      this.Repository = repository;
      this.TransactionCache = transactionCache;
    }

    private IIotaRepository Repository { get; }

    private ITransactionCache TransactionCache { get; }

    /// <inheritdoc />
    public async Task<List<Message>> GetMessagesByAddressAsync(Address address, IBundleParser bundleParser)
    {
      var result = new List<Message>();

      var cachedTransactions = await this.TransactionCache.LoadTransactionsByAddressAsync(address);
      foreach (var cachedTransaction in cachedTransactions)
      {
        result.Add(new Message(cachedTransaction.TransactionTrytes));
      }

      var transactionHashesFromTangle = await this.Repository.FindTransactionsByAddressesAsync(new List<Address> { address });
      foreach (var transactionHash in transactionHashesFromTangle.Hashes)
      {
        if (cachedTransactions.Any(h => h.TransactionHash.Value == transactionHash.Value))
        {
          continue;
        }

        var messages = bundleParser.ParseBundle(await this.Repository.GetBundleAsync(transactionHash));
        result.AddRange(messages);

        messages.ForEach(
          async m => await this.TransactionCache.SaveTransactionAsync(
                       new TransactionCacheItem { Address = address, TransactionHash = transactionHash, TransactionTrytes = m.Payload }));
      }

      return result;
    }

    /// <inheritdoc />
    public async Task SendMessageAsync(Message message)
    {
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
  }
}