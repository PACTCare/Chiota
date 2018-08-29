namespace Chiota.Messenger.Usecase.GetApprovedContacts
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  /// <summary>
  /// The get approved contacts response.
  /// </summary>
  public class GetApprovedContactsResponse
  {
    /// <summary>
    /// Gets or sets the contacts.
    /// </summary>
    public List<Contact> Contacts { get; set; }
  }
}