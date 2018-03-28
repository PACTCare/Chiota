namespace Chiota.Models
{
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class Contact
  {
    public string Name { get; set; }

    public string ImageUrl { get; set; }

    public string ContactAdress { get; set; }

    public string ChatAdress { get; set; }

    public string PublicKeyAdress { get; set; }

    public IAsymmetricKey PublicNtruKey { get; set; }

    public bool Request { get; set; }

    public bool Rejected { get; set; }
  }
}
