namespace Chiota.Messenger.Entity
{
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class Contact
  {
    public string Name { get; set; }

    public string ImageHash { get; set; }

    public string ChatAddress { get; set; }

    public string ChatKeyAddress { get; set; }

    public string PublicKeyAddress { get; set; }

    public bool Request { get; set; }

    public bool Rejected { get; set; }

    public string ContactAddress { get; set; }

    public IAsymmetricKey NtruKey { get; set; }
  }
}