namespace Chiota.Messenger.Usecase.GetApprovedContacts
{
  using Tangle.Net.Entity;

  /// <summary>
  /// The get approved contacts request.
  /// </summary>
  public class GetApprovedContactsRequest
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