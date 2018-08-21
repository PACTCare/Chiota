namespace Chiota.Messenger.Usecase.AddContact
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The add contact request.
  /// </summary>
  public class AddContactRequest
  {
    /// <summary>
    /// Gets or sets the contact.
    /// </summary>
    public Address ContactAddress { get; set; }

    /// <summary>
    /// Gets or sets the ntru key.
    /// </summary>
    public IAsymmetricKey NtruKey { get; set; }
  }
}