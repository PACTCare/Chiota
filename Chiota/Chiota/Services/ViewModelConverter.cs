namespace Chiota.Services
{
  using Chiota.Models;
  using Chiota.ViewModels;

  public class ViewModelConverter
  {
    public static ContactListViewModel ContactToViewModel(Contact contact, User user, ViewCellObject viewCellObject)
    {
      return new ContactListViewModel(user, viewCellObject)
               {
                 Name = contact.Name,
                 ImageUrl = contact.ImageUrl,
                 ChatAddress = contact.ChatAddress,
                 ContactAddress = contact.ContactAddress,
                 PublicKeyAddress = contact.PublicKeyAddress,
                 PublicNtruKey = contact.PublicNtruKey,
                 Request = contact.Request,
                 Rejected = contact.Rejected
               };
    }
  }
}
