namespace Chiota.Messenger.Usecase.SendMessage
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The send message request.
  /// </summary>
  public class SendMessageRequest
  {
    /// <summary>
    /// Gets or sets the chat address.
    /// </summary>
    public Address ChatAddress { get; set; }

    /// <summary>
    /// Gets or sets the key pair.
    /// </summary>
    public IAsymmetricKeyPair KeyPair { get; set; }

    /// <summary>
    /// Gets or sets the message.
    /// </summary>
    public string Message { get; set; }

    /// <summary>
    /// Gets or sets the user public key address.
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
  }
}