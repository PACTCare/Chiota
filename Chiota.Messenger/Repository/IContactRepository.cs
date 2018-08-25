namespace Chiota.Messenger.Repository
{
  using System.Threading.Tasks;

  /// <summary>
  /// The ContactRepository interface.
  /// </summary>
  public interface IContactRepository
  {
    /// <summary>
    /// The add contact async.
    /// </summary>
    /// <param name="address">
    /// The address.
    /// </param>
    /// <param name="accepted">
    /// The accepted.
    /// </param>
    /// <param name="publicKeyAddress">
    /// The public Key Address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task AddContactAsync(string address, bool accepted, string publicKeyAddress);
  }
}