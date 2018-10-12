namespace Chiota.Messenger.Entity
{
  using Tangle.Net.Entity;

  /// <summary>
  /// Message type internally used by the Tangle Messenger
  /// </summary>
  public class Message
  {
    public Message(TryteString payload, Address receiver = null)
    {
      this.Payload = payload;
      this.Receiver = receiver;
    }

    /// <summary>
    /// The messages payload. Aggregated bundle transactions
    /// </summary>
    public TryteString Payload { get; }

    /// <summary>
    /// Receiver of the message
    /// </summary>
    public Address Receiver { get; }
  }
}