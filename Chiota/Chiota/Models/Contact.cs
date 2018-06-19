namespace Chiota.Models
{
  using System.ComponentModel;
  using System.Runtime.CompilerServices;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class Contact : INotifyPropertyChanged
  {
    public event PropertyChangedEventHandler PropertyChanged;

    public string Name { get; set; }

    public string ImageUrl { get; set; }

    public string ContactAddress { get; set; }

    public string ChatAddress { get; set; }

    public string ChatKeyAddress { get; set; }

    public string PublicKeyAddress { get; set; }

    public IAsymmetricKey NtruKey { get; set; }

    public bool Request { get; set; }

    public bool Rejected { get; set; }

    public void RaisePropertyChanged([CallerMemberName] string propertyName = "")
    {
      this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
  }
}
