namespace Chiota.Messenger.Usecase.CheckUser
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class CheckUserRequest
  {
    /// <summary>
    /// Public key of the user to check (See CreateUserResponse)
    /// </summary>
    public IAsymmetricKey PublicKey { get; set; }

    /// <summary>
    /// Public Key address of the user (See CreateUserResponse)
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// (Contact) request address of the user (See CreateUserResponse)
    /// </summary>
    public Address RequestAddress { get; set; }

    /// <summary>
    /// Seed associated with the user
    /// </summary>
    public Seed Seed { get; set; }
  }
}