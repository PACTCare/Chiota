namespace Chiota.Messenger.Usecase.DeclineContact
{
  using Tangle.Net.Entity;

  public class DeclineContactRequest
  {
    /// <summary>
    /// Chat address included in the contacts request
    /// </summary>
    public Address ContactChatAddress { get; set; }

    /// <summary>
    /// Public key address of the current user
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
  }
}