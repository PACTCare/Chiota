namespace Chiota.Messenger.Repository
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;

  /// <summary>
  /// The ContactRepository interface.
  /// </summary>
  public interface IContactRepository
  {
    /// <summary>
    /// The add contact async.
    /// </summary>
    /// <param name="contact">
    /// The contact.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task AddContactAsync(Contact contact);
  }
}