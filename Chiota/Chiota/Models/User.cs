namespace Chiota.Models
{
  using Newtonsoft.Json;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class User
  {
    public string Name { get; set; }

    public string ImageHash { get; set; }

    public string RequestAddress { get; set; }

    public string PublicKeyAddress { get; set; }

    public bool StoreSeed { get; set; }

    [JsonIgnore]
    public IAsymmetricKeyPair NtruKeyPair { get; set; }

    public string Seed { get; set; }
  }
}
