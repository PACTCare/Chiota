namespace Chiota.Messenger.Tests.Cache
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;

  using Tangle.Net.Entity;

  /// <summary>
  /// The in memory transaction cache.
  /// </summary>
  internal class InMemoryTransactionCache : ITransactionCache
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryTransactionCache"/> class.
    /// </summary>
    public InMemoryTransactionCache()
    {
      this.Items = new List<TransactionCacheItem>();
    }

    /// <summary>
    /// Gets the items.
    /// </summary>
    public List<TransactionCacheItem> Items { get; }

    /// <inheritdoc />
    public Task FlushAsync()
    {
      return null;
    }

    /// <summary>
    /// The load transactions by address.
    /// </summary>
    /// <param name="address">
    /// The address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    public async Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address)
    {
      return this.Items.Where(i => i.Address.Value == address.Value).ToList();
    }

    /// <summary>
    /// The save transaction.
    /// </summary>
    /// <param name="item">
    /// The item.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    public async Task SaveTransactionAsync(TransactionCacheItem item)
    {
      this.Items.Add(item);
    }
  }
}