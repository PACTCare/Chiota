namespace Chiota.Messenger.Usecase.GetMessages
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  public class GetMessagesResponse : BaseResponse
  {
    public Address CurrentChatAddress { get; set; }

    public List<ChatMessage> Messages { get; set; }
  }
}