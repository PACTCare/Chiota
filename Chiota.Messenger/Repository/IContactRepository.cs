namespace Chiota.Messenger.Repository
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

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
    /// The public Key ContactAddress.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task AddContactAsync(string address, bool accepted, string publicKeyAddress);

    /// <summary>
    /// The load contact information by address async.
    /// </summary>
    /// <param name="address">
    /// The address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task<ContactInformation> LoadContactInformationByAddressAsync(Address address);

    /// <summary>
    /// The load contacts async.
    /// </summary>
    /// <param name="publicKeyAddress">
    /// The public key address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task<List<Contact>> LoadContactsAsync(string publicKeyAddress);
  }
}