namespace Chiota.Messenger.Usecase
{
  /// <summary>
  /// The base response.
  /// </summary>
  public abstract class BaseResponse
  {
    /// <summary>
    /// Response Code used to express the success or failure of a usecase. Base of all responses
    /// </summary>
    public ResponseCode Code { get; set; }
  }
}