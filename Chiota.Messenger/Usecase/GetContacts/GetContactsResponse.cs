namespace Chiota.Messenger.Usecase.GetContacts
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  /// <summary>
  /// The get approved contacts response.
  /// </summary>
  public class GetContactsResponse : BaseResponse
  {
    /// <summary>
    /// Gets or sets the contacts.
    /// </summary>
    public List<Contact> ApprovedContacts { get; set; }

    /// <summary>
    /// Gets or sets the pending contact requests.
    /// </summary>
    public List<Contact> PendingContactRequests { get; set; }
  }
}