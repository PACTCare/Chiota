namespace Chiota.Models
{
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class Contact
  {
    public string Name { get; set; }

    public string ImageUrl { get; set; }

    public string ContactAddress { get; set; }

    public string ChatAddress { get; set; }

    public string PublicKeyAddress { get; set; }

    public IAsymmetricKey PublicNtruKey { get; set; }

    public bool Request { get; set; }

    public bool Rejected { get; set; }
  }
}
