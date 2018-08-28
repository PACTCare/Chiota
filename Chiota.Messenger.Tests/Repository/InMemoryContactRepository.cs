namespace Chiota.Messenger.Tests.Repository
{
  using System.Collections.Generic;
  using System.Diagnostics.CodeAnalysis;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;

  /// <summary>
  /// The in memory contact repository.
  /// </summary>
  [ExcludeFromCodeCoverage]
  internal class InMemoryContactRepository : IContactRepository
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryContactRepository"/> class.
    /// </summary>
    public InMemoryContactRepository()
    {
      this.PersistedContacts = new List<Contact>();
    }

    /// <summary>
    /// Gets the persisted contacts.
    /// </summary>
    public List<Contact> PersistedContacts { get; }

    /// <inheritdoc />
    public async Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
      this.PersistedContacts.Add(new Contact { ChatAddress = address, Request = accepted, PublicKeyAddress = publicKeyAddress });
    }

    /// <inheritdoc />
    public async Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
    {
      return this.PersistedContacts.Where(c => c.PublicKeyAddress == publicKeyAddress).ToList();
    }
  }
}