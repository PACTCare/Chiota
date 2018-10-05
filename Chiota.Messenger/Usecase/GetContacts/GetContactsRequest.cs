namespace Chiota.Messenger.Usecase.GetContacts
{
  using Tangle.Net.Entity;

  /// <summary>
  /// The get approved contacts request.
  /// </summary>
  public class GetContactsRequest
  {
    public Address ContactRequestAddress { get; set; }

    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// If set to true, checks all pending contacts to determine whether they are accepted or not.
    /// Normally not needed since the information is stored in the IContactRepository (locally).
    /// Useful to import a existing seed into a new device
    /// </summary>
    public bool DoCrossCheck { get; set; }
  }
}