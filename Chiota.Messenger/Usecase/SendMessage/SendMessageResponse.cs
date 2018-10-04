namespace Chiota.Messenger.Usecase.SendMessage
{
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The send message response.
  /// </summary>
  public class SendMessageResponse : BaseResponse
  {
    /// <summary>
    /// ChatKeyPair from the request or the generated one, if the request pair was not set
    /// </summary>
    public IAsymmetricKeyPair ChatKeyPair { get; set; }
  }
}