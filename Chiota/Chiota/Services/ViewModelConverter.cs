namespace Chiota.Services
{
  using Chiota.Messenger.Entity;
  using Chiota.Models;
  using Chiota.ViewModels;

  public static class ViewModelConverter
  {
    public static ContactListViewModel ContactToViewModel(Contact contact, ViewCellObject viewCellObject)
    {
      return new ContactListViewModel(viewCellObject)
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
