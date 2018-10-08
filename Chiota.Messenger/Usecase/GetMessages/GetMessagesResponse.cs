namespace Chiota.Messenger.Usecase.GetMessages
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class GetMessagesResponse : BaseResponse
  {
    /// <summary>
    /// Current address of the conversation. Acts as a pointer. Input into request to start getting message from that point in conversation
    /// </summary>
    public Address CurrentChatAddress { get; set; }

    /// <summary>
    /// List of messages
    /// </summary>
    public List<ChatMessage> Messages { get; set; }

    /// <summary>
    /// ChatKeyPair from the request or the generated one, if the request pair was not set
    /// </summary>
    public IAsymmetricKeyPair ChatKeyPair { get; set; }
  }
}