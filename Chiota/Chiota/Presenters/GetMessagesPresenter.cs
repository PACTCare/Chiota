namespace Chiota.Presenters
{
  using System.Collections.Generic;
  using System.Linq;

  using Chiota.ViewModels;

  using Pact.Palantir.Entity;
  using Pact.Palantir.Usecase.GetMessages;

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
                 ProfileImage = contact.ImagePath
               }).ToList();
    }
  }
}