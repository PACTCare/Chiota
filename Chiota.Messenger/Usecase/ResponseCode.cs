namespace Chiota.Messenger.Usecase
{
  /// <summary>
  /// The response codes.
  /// </summary>
  public enum ResponseCode
  {
    /// <summary>
    /// Returned if the use case is executed successfully
    /// </summary>
    Success = 1,

    /// <summary>
    /// Error code that is returned if an error occurs while adding the contact via IContactRepository
    /// </summary>
    CannotAddContact = -1,

    /// <summary>
    /// Error code that is returned if an error occurs while sending data via messenger
    /// </summary>
    MessengerException = -2,

    /// <summary>
    /// The unkown exception.
    /// </summary>
    UnkownException = -3,

    /// <summary>
    /// Error code that is returned when no contact information is present while calling IContactInformationRepository::LoadContactInformationByAddressAsync
    /// </summary>
    NoContactInformationPresent = -4,

    /// <summary>
    /// Error code that is returned when more than one valid contact information entry is found at an address
    /// </summary>
    AmbiguousContactInformation = -5
  }
}