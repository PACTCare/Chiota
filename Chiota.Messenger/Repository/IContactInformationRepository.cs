namespace Chiota.Messenger.Repository
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  /// <summary>
  /// The ContactInformationRepository interface.
  /// </summary>
  public interface IContactInformationRepository
  {
    /// <summary>
    /// The load contact information by address.
    /// </summary>
    /// <param name="address">
    /// The address.
    /// </param>
    /// <returns>
    /// The <see cref="ContactInformation"/>.
    /// </returns>
    Task<ContactInformation> LoadContactInformationByAddressAsync(Address address);
  }
}