namespace Chiota.Messenger.Entity
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The contact information.
  /// </summary>
  public class ContactInformation
  {
    /// <summary>
    /// Gets or sets the address.
    /// </summary>
    public Address ContactAddress { get; set; }

    /// <summary>
    /// Gets or sets the ntru key.
    /// </summary>
    public IAsymmetricKey NtruKey { get; set; }
  }
}