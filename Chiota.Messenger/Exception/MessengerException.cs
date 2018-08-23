namespace Chiota.Messenger.Exception
{
  using System;

  using Chiota.Messenger.Usecase;

  /// <summary>
  /// The messenger exception.
  /// </summary>
  public class MessengerException : Exception
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="MessengerException"/> class.
    /// </summary>
    /// <param name="code">
    /// The code.
    /// </param>
    /// <param name="innerException">
    /// The inner exception.
    /// </param>
    public MessengerException(ResponseCode code, Exception innerException = null)
      : base(code.ToString(), innerException)
    {
      this.Code = code;
    }

    /// <summary>
    /// Gets the code.
    /// </summary>
    public ResponseCode Code { get; }
  }
}