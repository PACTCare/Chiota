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
                 ImageHash = ChiotaConstants.IpfsHashGateway + contact.ImageHash,
                 ChatAddress = contact.ChatAddress,
                 ChatKeyAddress = contact.ChatKeyAddress,
                 ContactAddress = contact.ContactAddress,
                 PublicKeyAddress = contact.PublicKeyAddress,
                 NtruKey = contact.NtruKey,
                 Request = contact.Request,
                 Rejected = contact.Rejected
               };
    }
  }
}
