namespace Chiota.Messenger.Cucumber.Repository
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;

  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Repository;

  public class EmptyContactRepository : AbstractTangleContactRepository
  {
    /// <inheritdoc />
    public EmptyContactRepository(IIotaRepository iotaRepository, ISignatureValidator signatureValidator)
      : base(iotaRepository, signatureValidator)
    {
    }

    /// <inheritdoc />
    public async override Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
    }

    /// <inheritdoc />
    public async override Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
    {
      return new List<Contact>();
    }
  }
}