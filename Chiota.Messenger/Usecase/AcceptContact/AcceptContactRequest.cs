namespace Chiota.Messenger.Usecase.AcceptContact
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The accept contact request.
  /// </summary>
  public class AcceptContactRequest
  {
    /// <summary>
    /// Gets or sets the chat address.
    /// </summary>
    public Address ChatAddress { get; set; }

    /// <summary>
    /// Gets or sets the chat key address.
    /// </summary>
    public Address ChatKeyAddress { get; set; }

    /// <summary>
    /// Gets or sets the contact address.
    /// </summary>
    public Address ContactAddress { get; set; }

    /// <summary>
    /// Gets or sets the public key address.
    /// </summary>
    public Address ContactPublicKeyAddress { get; set; }

    /// <summary>
    /// Gets or sets the user image hash.
    /// </summary>
    public string UserImageHash { get; set; }

    /// <summary>
    /// Gets or sets the user key pair.
    /// </summary>
    public IAsymmetricKeyPair UserKeyPair { get; set; }

    /// <summary>
    /// Gets or sets the user name.
    /// </summary>
    public string UserName { get; set; }

    /// <summary>
    /// Gets or sets the user public key address.
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
  }
}