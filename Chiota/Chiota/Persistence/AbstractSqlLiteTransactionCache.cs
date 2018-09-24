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
      Connection?.CreateTableAsync<SqLiteMessage>();
    }

    /// <summary>
    /// Gets the connection.
    /// </summary>
    public abstract SQLiteAsyncConnection Connection { get; }

    /// <inheritdoc />
    public async Task FlushAsync()
    {
      await Connection.QueryAsync<SqLiteMessage>("DELETE FROM SqLiteMessage");
    }

    /// <inheritdoc />
    public async Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address)
    {
      var cachedItems = await Connection.QueryAsync<SqLiteMessage>(
                          "SELECT * FROM SqLiteMessage WHERE ChatAddress = ? ORDER BY Id",
                          address.Value);

      return cachedItems.Select(
        item => new TransactionCacheItem
                  {
                    Address = new Address(item.ChatAddress),
                    TransactionHash = new Hash(item.TransactionHash),
                    TransactionTrytes = new TryteString(item.MessageTryteString)
                  }).ToList();
    }

    /// <inheritdoc />
    public async Task SaveTransactionAsync(TransactionCacheItem item)
    {
      var sqlLiteMessage = new SqLiteMessage
                             {
                               TransactionHash = item.TransactionHash.Value,
                               ChatAddress = item.Address.Value,
                               MessageTryteString = item.TransactionTrytes.Value
                             };

      await Connection.InsertAsync(sqlLiteMessage);
    }
  }
}