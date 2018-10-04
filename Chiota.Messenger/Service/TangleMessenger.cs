namespace Chiota.Messenger.Service
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
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
    public TangleMessenger(IIotaRepository repository, ITransactionCache transactionCache)
    {
      this.Repository = repository;
      this.TransactionCache = transactionCache;
    }

    private IIotaRepository Repository { get; }

    private ITransactionCache TransactionCache { get; }

    /// <inheritdoc />
    public async Task<List<Message>> GetMessagesByAddressAsync(Address address)
    {
      var transactions = await this.LoadTransactionsAsync(address);
      var bundles = ExtractBundles(transactions);
      var sortedBundles = SortBundles(bundles);

      return sortedBundles.Select(
          bundle => new Message(bundle.Transactions.Aggregate(new TryteString(), (current, tryteString) => current.Concat(tryteString.Fragment)), address))
        .ToList();
    }

    /// <inheritdoc />
    public async Task SendMessageAsync(Message message)
    {
      try
      {
        var bundle = new Bundle();
        bundle.AddTransfer(
          new Transfer { Address = message.Receiver, Message = message.Payload, Tag = Constants.Tag, Timestamp = Timestamp.UnixSecondsTimestamp });

        bundle.Finalize();
        bundle.Sign();

        await this.Repository.SendTrytesAsync(bundle.Transactions);
      }
      catch (Exception exception)
      {
        throw new MessengerException(ResponseCode.MessengerException, exception);
      }
    }

    private static IEnumerable<Bundle> ExtractBundles(IEnumerable<Transaction> transactions)
    {
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

    private static IEnumerable<Bundle> SortBundles(IEnumerable<Bundle> bundles)
    {
      return bundles.Select(bundle => bundle.Transactions.OrderBy(t => t.CurrentIndex).ToList())
        .Select(sortedTransactions => new Bundle { Transactions = sortedTransactions });
    }

    private async Task<List<Transaction>> LoadTransactionsAsync(Address address)
    {
      var cachedTransactions = await this.TransactionCache.LoadTransactionsByAddressAsync(address);
      var transactionHashes = await this.Repository.FindTransactionsByAddressesAsync(new List<Address> { address });

      var newHashes = new List<Hash>();
      foreach (var transactionHash in transactionHashes.Hashes)
      {
        if (cachedTransactions.Any(h => h.TransactionHash.Value == transactionHash.Value))
        {
          continue;
        }

        newHashes.Add(transactionHash);
      }

      var transactions = new List<Transaction>();
      transactions.AddRange(cachedTransactions.Select(c => Transaction.FromTrytes(c.TransactionTrytes)));

      var newTransactionTrytes = await this.Repository.GetTrytesAsync(newHashes);
      foreach (var transactionTryte in newTransactionTrytes)
      {
        var transaction = Transaction.FromTrytes(transactionTryte);
        transactions.Add(transaction);

        await this.TransactionCache.SaveTransactionAsync(
          new TransactionCacheItem { Address = address, TransactionHash = transaction.Hash, TransactionTrytes = transactionTryte });
      }

      return transactions;
    }
  }
}