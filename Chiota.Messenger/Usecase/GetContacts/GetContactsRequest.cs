namespace Chiota.Messenger.Usecase.GetContacts
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class GetContactsRequest
  {
    /// <summary>
    /// The current user request address (See CreateUserResponse)
    /// </summary>
    public Address RequestAddress { get; set; }

    /// <summary>
    /// The current user public key address (See CreateUserResponse)
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// The current user key pair. Used to decrypt contact requests
    /// </summary>
    public IAsymmetricKeyPair KeyPair { get; set; }

    /// <summary>
    /// If set to true, checks all pending contacts to determine whether they are accepted or not.
    /// Normally not needed since the information is stored in the IContactRepository (locally).
    /// Useful to import a existing seed into a new device
    /// </summary>
    public bool DoCrossCheck { get; set; }
  }
}