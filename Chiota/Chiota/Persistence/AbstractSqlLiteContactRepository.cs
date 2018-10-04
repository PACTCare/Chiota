namespace Chiota.Persistence
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;
  using Chiota.Models.SqLite;

  using SQLite;

  using Tangle.Net.Cryptography.Signing;

  /// <summary>
  /// The abstract sql lite db.
  /// </summary>
  public abstract class AbstractSqlLiteContactRepository : AbstractTangleContactRepository
  {
    /// <inheritdoc />
    protected AbstractSqlLiteContactRepository(IMessenger messenger, ISignatureValidator signatureValidator)
      : base(messenger, signatureValidator)
    {
      // There needs to be a better way for this
      Connection?.CreateTableAsync<SqLiteContacts>();
    }

    /// <summary>
    /// Gets the connection.
    /// </summary>
    public abstract SQLiteAsyncConnection Connection { get; }

    /// <inheritdoc />
    public override async Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
      await Connection.InsertAsync(new SqLiteContacts { ChatAddress = address, Accepted = accepted, PublicKeyAddress = publicKeyAddress });
    }

    /// <inheritdoc />
    public override async Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
    {
      var contactsResult = await Connection.QueryAsync<SqLiteContacts>(
                             "SELECT * FROM SqLiteContacts WHERE PublicKeyAddress = ? ORDER BY Id",
                             publicKeyAddress);

      return contactsResult.Where(c => c.Accepted).Select(c => new Contact { ChatAddress = c.ChatAddress, Rejected = !c.Accepted }).ToList();
    }
  }
}