namespace Chiota.Messenger.Entity
{
  using System;

  public class ChatMessage
  {
    /// <summary>
    /// The messages timestamp
    /// </summary>
    public DateTime Date { get; set; }

    /// <summary>
    /// Decrypted message
    /// </summary>
    public string Message { get; set; }

    /// <summary>
    /// First 30 chars of the senders public key
    /// </summary>
    public string Signature { get; set; }
  }
}