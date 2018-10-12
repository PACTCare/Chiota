namespace Chiota.Messenger.Entity
{
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class Contact
  {
    /// <summary>
    /// The contacts name
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Path to the users image (in Chiota it is an IPFS hash)
    /// </summary>
    public string ImagePath { get; set; }

    /// <summary>
    /// The current users chat address with this contact
    /// </summary>
    public string ChatAddress { get; set; }

    /// <summary>
    /// The public key address for the chat with this contact
    /// </summary>
    public string ChatKeyAddress { get; set; }

    /// <summary>
    /// Address where the contacts public key is stored
    /// </summary>
    public string PublicKeyAddress { get; set; }

    /// <summary>
    /// Indicates whether this contact sent the current user a contact request
    /// </summary>
    public bool Request { get; set; }

    /// <summary>
    /// Indicates whether this contact was rejected
    /// </summary>
    public bool Rejected { get; set; }

    /// <summary>
    /// The address used to add this contact
    /// </summary>
    public string ContactAddress { get; set; }

    /// <summary>
    /// Public key of the contact
    /// </summary>
    public IAsymmetricKey PublicKey { get; set; }
  }
}