namespace Chiota.Messenger.Usecase.AddContact
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class AddContactRequest
  {
    /// <summary>
    /// Request address of the contact that should be added
    /// </summary>
    public Address ContactAddress { get; set; }

    /// <summary>
    /// Optional: Image that will be shown to the added contact within the contact request
    /// </summary>
    public string ImagePath { get; set; }

    /// <summary>
    /// Current user name. Will be shown to the contact within the contact request
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Public key address of the current user
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// Request address of the current user
    /// </summary>
    public Address RequestAddress { get; set; }

    /// <summary>
    /// Current user public key. Used to encrypt the nonce of the answer to the contact request
    /// </summary>
    public IAsymmetricKey UserPublicKey { get; set; }
  }
}