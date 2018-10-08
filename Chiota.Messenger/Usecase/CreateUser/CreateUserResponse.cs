namespace Chiota.Messenger.Usecase.CreateUser
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class CreateUserResponse : BaseResponse
  {
    /// <summary>
    /// Address where the users' public key is stored
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// Other users can add the user by using this address
    /// </summary>
    public Address RequestAddress { get; set; }

    /// <summary>
    /// Key pair generated from seed, used for encryption
    /// </summary>
    public IAsymmetricKeyPair NtruKeyPair { get; set; }
  }
}