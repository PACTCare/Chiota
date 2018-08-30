namespace Chiota.Messenger.Usecase.GetContacts
{
  using Tangle.Net.Entity;

  /// <summary>
  /// The get approved contacts request.
  /// </summary>
  public class GetContactsRequest
  {
    /// <summary>
    /// Gets or sets the contact request address.
    /// </summary>
    public Address ContactRequestAddress { get; set; }

    /// <summary>
    /// Gets or sets the public key address.
    /// </summary>
    public Address PublicKeyAddress { get; set; }
  }
}