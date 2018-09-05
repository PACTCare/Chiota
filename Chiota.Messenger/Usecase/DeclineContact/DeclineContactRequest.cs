namespace Chiota.Messenger.Usecase.DeclineContact
{
  using Tangle.Net.Entity;

  /// <summary>
  /// The decline contact request.
  /// </summary>
  public class DeclineContactRequest
  {
    /// <summary>
    /// Gets or sets the contact chat address.
    /// </summary>
    public Address ContactChatAddress { get; set; }

    /// <summary>
    /// Gets or sets the user public key address.
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
  }
}