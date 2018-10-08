namespace Chiota.Messenger.Usecase.SendMessage
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The send message request.
  /// </summary>
  public class SendMessageRequest
  {
    public Address ChatAddress { get; set; }

    /// <summary>
    /// Optional. Will be generated at runtime, if necessary. ChatKeyAddress and UserKeyPair must be set, if ChatKeyPair is null
    /// </summary>
    public IAsymmetricKeyPair ChatKeyPair { get; set; }

    /// <summary>
    /// Must be set if ChatKeyPair is null
    /// </summary>
    public Address ChatKeyAddress { get; set; }

    /// <summary>
    /// Must be set if ChatKeyPair is null
    /// </summary>
    public IAsymmetricKeyPair UserKeyPair { get; set; }

    /// <summary>
    /// The message to send
    /// </summary>
    public string Message { get; set; }

    /// <summary>
    /// Public key address of the current user
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
  }
}