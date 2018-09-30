namespace Chiota.Presenters
{
  using System.Collections.Generic;
  using System.Linq;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Usecase.GetMessages;
  using Chiota.ViewModels;

  public static class GetMessagesPresenter
  {
    public static List<MessageViewModel> Present(GetMessagesResponse response, Contact contact)
    {
      return response.Messages.Select(
        m => new MessageViewModel
               {
                 Text = m.Message,
                 MessagDateTime = m.Date.ToLocalTime(),
                 IsIncoming = m.Signature == contact.PublicKeyAddress.Substring(0, 30),
                 ProfileImage = contact.ImageHash
               }).ToList();
    }
  }
}