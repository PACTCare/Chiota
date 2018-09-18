namespace Chiota.Messenger.Usecase.CheckUser
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class CheckUserRequest
  {
    public IAsymmetricKey PublicKey { get; set; }

    public Address PublicKeyAddress { get; set; }

    public Address RequestAddress { get; set; }

    public Seed Seed { get; set; }
  }
}