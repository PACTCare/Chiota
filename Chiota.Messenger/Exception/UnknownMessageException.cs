namespace Chiota.Messenger.Exception
{
  using System;

  /// <inheritdoc />
  public class UnknownMessageException : Exception
  {
    public UnknownMessageException(string messageType) : base($"Message type >{messageType}< is unkown.")
    {
    }
  }
}