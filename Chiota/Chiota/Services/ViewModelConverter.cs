namespace Chiota.Services
{
  using Chiota.Models;
  using Chiota.ViewModels;

  public class ViewModelConverter
  {
    public static ContactListViewModel ContactToViewModel(Contact contact, User user)
    {
      return new ContactListViewModel(user)
               {
                 Name = contact.Name,
                 ImageUrl = contact.ImageUrl,
                 ChatAdress = contact.ChatAdress,
                 ContactAdress = contact.ContactAdress,
                 PublicKeyAdress = contact.PublicKeyAdress,
                 PublicNtruKey = contact.PublicNtruKey,
                 Request = contact.Request,
                 Rejected = contact.Rejected
               };
    }
  }
}
