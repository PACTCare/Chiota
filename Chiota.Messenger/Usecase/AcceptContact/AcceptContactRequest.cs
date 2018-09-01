namespace Chiota.Messenger.Usecase.AcceptContact
{
  using Tangle.Net.Entity;

  /// <summary>
  /// The accept contact request.
  /// </summary>
  public class AcceptContactRequest
  {
    /// <summary>
    /// Gets or sets the public key address.
    /// </summary>
    public Address ContactPublicKeyAddress { get; set; }

    public Address ChatAddress { get; set; }
  }
}