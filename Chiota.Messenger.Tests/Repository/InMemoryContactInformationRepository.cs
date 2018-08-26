namespace Chiota.Messenger.Tests.Repository
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The in memory contact information repository.
  /// </summary>
  public class InMemoryContactInformationRepository : IContactInformationRepository
  {
    /// <summary>
    /// The ntru key pair.
    /// </summary>
    internal static IAsymmetricKeyPair NtruKeyPair =>
      new NtruKeyExchange(NTRUParamSets.NTRUParamNames.A2011743).CreateAsymmetricKeyPair(
        Seed.Random().Value.ToLower(),
        Seed.Random().Value.ToLower());

    /// <inheritdoc />
    public async Task<ContactInformation> LoadContactInformationByAddressAsync(Address address)
    {
      return new ContactInformation { ContactAddress = address, NtruKey = NtruKeyPair.PublicKey };
    }
  }
}