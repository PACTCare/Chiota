namespace Chiota.Messenger.Usecase.GetMessages
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  public class GetMessagesResponse : BaseResponse
  {
    public List<ChatMessage> Messages { get; set; }
  }
}