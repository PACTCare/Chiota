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
    /// <summary>
    /// The load transactions by address.
    /// </summary>
    /// <param name="address">
    /// The address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address);

    /// <summary>
    /// The save transaction.
    /// </summary>
    /// <param name="item">
    /// The item.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task SaveTransactionAsync(TransactionCacheItem item);
  }
}