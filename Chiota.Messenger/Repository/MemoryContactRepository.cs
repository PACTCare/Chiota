namespace Chiota.Messenger.Repository
{
  using System.Collections.Generic;
  using System.Diagnostics.CodeAnalysis;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Service;

  using Tangle.Net.Cryptography.Signing;

  [ExcludeFromCodeCoverage]
  public class MemoryContactRepository : AbstractTangleContactRepository
  {
    public MemoryContactRepository(IMessenger messenger, ISignatureValidator signatureValidator)
      : base(messenger, signatureValidator)
    {
      this.PersistedContacts = new List<Contact>();
    }

    public List<Contact> PersistedContacts { get; }

    /// <inheritdoc />
    public async override Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
      this.PersistedContacts.Add(new Contact { ChatAddress = address, Rejected = !accepted, PublicKeyAddress = publicKeyAddress });
    }

    /// <inheritdoc />
    public async override Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
    {
      return this.PersistedContacts.Where(c => c.PublicKeyAddress == publicKeyAddress && !c.Rejected).ToList();
    }
  }
}