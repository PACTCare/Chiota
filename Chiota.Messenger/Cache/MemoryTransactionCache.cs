namespace Chiota.Messenger.Cache
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Tangle.Net.Entity;

  public class MemoryTransactionCache : ITransactionCache
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="MemoryTransactionCache"/> class.
    /// </summary>
    public MemoryTransactionCache()
    {
      this.Items = new List<TransactionCacheItem>();
    }

    public List<TransactionCacheItem> Items { get; }

    /// <inheritdoc />
    public async Task FlushAsync()
    {
      this.Items.Clear();
    }

    public async Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address)
    {
      return this.Items.Where(i => i.Address.Value == address.Value).ToList();
    }

    public async Task SaveTransactionAsync(TransactionCacheItem item)
    {
      this.Items.Add(item);
    }
  }
}