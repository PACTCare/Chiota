namespace Chiota.Persistence
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
  using Chiota.Models.SqLite;

  using SQLite;

  using Tangle.Net.Entity;

  /// <summary>
  /// The abstract sql lite transaction cache.
  /// </summary>
  public abstract class AbstractSqlLiteTransactionCache : ITransactionCache
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="AbstractSqlLiteTransactionCache"/> class.
    /// </summary>
    public AbstractSqlLiteTransactionCache()
    {
      this.Connection?.CreateTableAsync<SqLiteMessage>();
    }

    /// <summary>
    /// Gets the connection.
    /// </summary>
    public abstract SQLiteAsyncConnection Connection { get; }

    /// <inheritdoc />
    public async Task<List<TransactionCacheItem>> LoadTransactionsByAddress(Address address)
    {
      var cachedItems = await this.Connection.QueryAsync<SqLiteMessage>(
                          "SELECT * FROM SqLiteMessage WHERE ChatAddress = ? ORDER BY Id",
                          address.Value);

      return cachedItems.Select(
        item => new TransactionCacheItem
                  {
                    Address = new Address(item.ChatAddress),
                    TransactionHash = new Hash(item.TransactionHash),
                    TransactionTrytes = TryteString.FromUtf8String(item.MessageTryteString)
                  }).ToList();
    }

    /// <inheritdoc />
    public async Task SaveTransaction(TransactionCacheItem item)
    {
      var sqlLiteMessage = new SqLiteMessage
                             {
                               TransactionHash = item.TransactionHash.Value,
                               ChatAddress = item.Address.Value,
                               MessageTryteString = item.TransactionTrytes.ToUtf8String()
                             };

      await this.Connection.InsertAsync(sqlLiteMessage);
    }
  }
}