namespace Chiota.Messenger.Entity
{
  using System.Collections.Generic;

  /// <summary>
  /// The message type.
  /// </summary>
  public static class MessageType
  {
    /// <summary>
    /// The key exchange.
    /// </summary>
    public const string KeyExchange = "KeyExchange";

    /// <summary>
    /// The request contact.
    /// </summary>
    public const string RequestContact = "RequestContact";

    /// <summary>
    /// Initializes static members of the <see cref="MessageType"/> class.
    /// </summary>
    static MessageType()
    {
      Types = new List<string> { RequestContact };
    }

    /// <summary>
    /// Gets or sets the types.
    /// </summary>
    public static List<string> Types { get; set; }
  }
}