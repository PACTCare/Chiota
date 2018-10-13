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
    /// Returned if no clear source of an error can be determined. Look at stacktrace for more details
    /// </summary>
    UnkownException = -3,

    /// <summary>
    /// Error code that is returned when no contact information is present while calling IContactInformationRepository::LoadContactInformationByAddressAsync
    /// </summary>
    NoContactInformationPresent = -4,

    /// <summary>
    /// Error code that is returned when contacts cannot be loaded
    /// </summary>
    ContactsUnavailable = -5,

    /// <summary>
    /// Error code that is returned when the password and salt for the chat can not be generated. This may be related to incorrect information published to the chat key address
    /// </summary>
    ChatPasswordAndSaltCannotBeGenerated = -6,

    /// <summary>
    /// Error code that is returned when the given message is too long (see Constants.MessageCharacterLimit)
    /// </summary>
    MessageTooLong = -7
  }
}