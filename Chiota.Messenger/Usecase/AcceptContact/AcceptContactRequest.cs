namespace Chiota.Messenger.Usecase.AcceptContact
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class AcceptContactRequest
  {
    /// <summary>
    /// The chat address that was passed along with the request. (See Contact from GetContactsUsecase)
    /// </summary>
    public Address ChatAddress { get; set; }

    /// <summary>
    /// The chat key address that was passed along with the request. (See Contact from GetContactsUsecase)
    /// </summary>
    public Address ChatKeyAddress { get; set; }

    /// <summary>
    /// The contact address that was passed along with the request. (See Contact from GetContactsUsecase)
    /// </summary>
    public Address ContactAddress { get; set; }

    /// <summary>
    /// The contact public key address that was passed along with the request. (See Contact from GetContactsUsecase)
    /// </summary>
    public Address ContactPublicKeyAddress { get; set; }

    /// <summary>
    /// The contact address of the current user. 
    /// </summary>
    public Address UserContactAddress { get; set; }

    /// <summary>
    /// Image path of the users avatar or similar
    /// </summary>
    public string UserImagePath { get; set; }

    /// <summary>
    /// The key pair of the current user. Used for chat encryption
    /// </summary>
    public IAsymmetricKeyPair UserKeyPair { get; set; }

    /// <summary>
    /// Current user name
    /// </summary>
    public string UserName { get; set; }

    /// <summary>
    /// The users public key address
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
  }
}