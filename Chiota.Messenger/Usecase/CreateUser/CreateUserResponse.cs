namespace Chiota.Messenger.Usecase.CreateUser
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class CreateUserResponse : BaseResponse
  {
    public Address PublicKeyAddress { get; set; }

    public Address RequestAddress { get; set; }

    public IAsymmetricKeyPair NtruKeyPair { get; set; }
  }
}