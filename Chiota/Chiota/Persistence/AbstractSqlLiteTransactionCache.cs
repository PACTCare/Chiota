using System;
using Chiota.Models.Database;

namespace Chiota.Persistence
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;

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
    }

    /// <inheritdoc />
    public async Task FlushAsync()
    {
    }

    /// <inheritdoc />
    public async Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address)
    {
            return null;
    }

    /// <inheritdoc />
    public async Task SaveTransactionAsync(TransactionCacheItem item)
    {
    }
  }
}