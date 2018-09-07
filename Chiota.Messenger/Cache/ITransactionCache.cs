namespace Chiota.Messenger.Cache
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Tangle.Net.Entity;

  /// <summary>
  /// The TransactionCache interface.
  /// </summary>
  public interface ITransactionCache
  {
    Task FlushAsync();

    Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address);

    Task SaveTransactionAsync(TransactionCacheItem item);
  }
}