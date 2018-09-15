namespace Chiota.Messenger.Entity
{
  using System.Collections.Generic;

  public static class MessageType
  {
    public const string AcceptContact = "AcceptContact";

    public const string ChatMessage = "ChatMessage";

    public const string KeyExchange = "KeyExchange";

    public const string RequestContact = "RequestContact";

    public const string CreateUser = "CreateUser";

    static MessageType()
    {
      Types = new List<string>
                {
                  RequestContact,
                  KeyExchange,
                  AcceptContact,
                  ChatMessage,
                  CreateUser
                };
    }

    public static List<string> Types { get; set; }
  }
}