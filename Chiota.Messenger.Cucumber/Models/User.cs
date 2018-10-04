namespace Chiota.Messenger.Cucumber.Models
{
  using System.Collections.Generic;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class User
  {
    public User()
    {
      this.Contacts = new List<Contact>();
    }

    public IAsymmetricKeyPair ChatKeyPair { get; set; }

    public List<Contact> Contacts { get; set; }

    public string Name { get; set; }

    public IAsymmetricKeyPair NtruKeyPair { get; set; }

    public Address PublicKeyAddress { get; set; }

    public Address RequestAddress { get; set; }

    public Seed Seed { get; set; }
  }
}