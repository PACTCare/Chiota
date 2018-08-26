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
    /// Gets or sets the image hash.
    /// </summary>
    public string ImageHash { get; set; }

    /// <summary>
    /// Gets or sets the name.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Gets or sets the public key address.
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// Gets or sets the request address.
    /// </summary>
    public Address RequestAddress { get; set; }
  }
}