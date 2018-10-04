namespace Chiota.Messenger.Cache
{
  using Tangle.Net.Entity;

  /// <summary>
  /// The transaction cache item.
  /// </summary>
  public class TransactionCacheItem
  {
    /// <summary>
    /// Gets or sets the chat address.
    /// </summary>
    public Address Address { get; set; }

    /// <summary>
    /// Gets or sets the message tryte string.
    /// </summary>
    public TransactionTrytes TransactionTrytes { get; set; }

    /// <summary>
    /// Gets or sets the transaction hash.
    /// </summary>
    public Hash TransactionHash { get; set; }
  }
}