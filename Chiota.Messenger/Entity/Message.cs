namespace Chiota.Messenger.Entity
{
  using Tangle.Net.Entity;

  /// <summary>
  /// The message.
  /// </summary>
  public class Message
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="Message"/> class.
    /// </summary>
    /// <param name="type">
    /// The type.
    /// </param>
    /// <param name="payload">
    /// The payload.
    /// </param>
    /// <param name="receiver">
    /// The receiver.
    /// </param>
    public Message(string type, TryteString payload, Address receiver)
    {
      this.Type = type;
      this.Payload = payload;
      this.Receiver = receiver;
    }

    /// <summary>
    /// The has known type.
    /// </summary>
    public bool HasKnownType => MessageType.Types.Contains(this.Type);

    /// <summary>
    /// Gets the payload.
    /// </summary>
    public TryteString Payload { get; }

    /// <summary>
    /// Gets the receiver.
    /// </summary>
    public Address Receiver { get; }

    /// <summary>
    /// Gets the type.
    /// </summary>
    public string Type { get; }
  }
}