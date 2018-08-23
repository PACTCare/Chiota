namespace Chiota.Persistence
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Repository;
  using Chiota.Models.SqLite;

  using SQLite;

  /// <summary>
  /// The abstract sql lite db.
  /// </summary>
  public abstract class AbstractSqlLiteDb : IContactRepository
  {
    /// <inheritdoc />
    public async Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
      await this.GetConnection().InsertAsync(new SqLiteContacts { ChatAddress = address, Accepted = accepted, PublicKeyAddress = publicKeyAddress });
    }

    /// <summary>
    /// The get connection.
    /// </summary>
    /// <returns>
    /// The <see cref="SQLiteAsyncConnection"/>.
    /// </returns>
    public abstract SQLiteAsyncConnection GetConnection();
  }
}