namespace Chiota.Messenger.Entity
{
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The contact.
  /// </summary>
  public class Contact
  {
    /// <summary>
    /// Gets or sets the contact address.
    /// </summary>
    public string ContactAddress { get; set; }

    public string Name { get; set; }

    public string ImageHash { get; set; }

    public string ChatAddress { get; set; }

    public string ChatKeyAddress { get; set; }

    public string PublicKeyAddress { get; set; }

    public IAsymmetricKey NtruKey { get; set; }

    public bool Requested { get; set; }

    public bool Rejected { get; set; }
  }
}