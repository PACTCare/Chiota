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
    /// Contact Addredd
    /// </summary>
    public Address ContactAddress { get; set; }

    /// <summary>
    /// Public key of the contact
    /// </summary>
    public IAsymmetricKey PublicKey { get; set; }
  }
}