namespace Chiota.Models
{
  using System.ComponentModel;
  using System.Runtime.CompilerServices;

  using Chiota.ViewModels;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class Contact : INotifyPropertyChanged
  {
    public event PropertyChangedEventHandler PropertyChanged;

    public string Name { get; set; }

    public string ImageUrl { get; set; }

    public string ContactAddress { get; set; }

    public string ChatAddress { get; set; }

    public string PublicKeyAddress { get; set; }

    public IAsymmetricKey PublicNtruKey { get; set; }

    public bool Request { get; set; }

    public bool Rejected { get; set; }

    public void RaisePropertyChanged([CallerMemberName] string propertyName = "")
    {
      this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public ContactListViewModel ToViewModel(ViewCellObject viewCellObject)
    {
      return new ContactListViewModel(viewCellObject)
               {
                 Name = this.Name,
                 ImageUrl = this.ImageUrl,
                 ChatAddress = this.ChatAddress,
                 ContactAddress = this.ContactAddress,
                 PublicKeyAddress = this.PublicKeyAddress,
                 PublicNtruKey = this.PublicNtruKey,
                 Request = this.Request,
                 Rejected = this.Rejected
               };
    }
  }
}
