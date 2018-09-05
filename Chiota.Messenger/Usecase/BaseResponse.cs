namespace Chiota.Messenger.Usecase
{
  /// <summary>
  /// The base response.
  /// </summary>
  public abstract class BaseResponse
  {
    /// <summary>
    /// Gets or sets the code.
    /// </summary>
    public ResponseCode Code { get; set; }
  }
}