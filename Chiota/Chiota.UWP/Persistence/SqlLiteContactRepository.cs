using System.Collections.Generic;
using System.Threading.Tasks;
using Chiota.Messenger.Entity;

namespace Chiota.UWP.Persistence
{
  using System.IO;

  using Chiota.Messenger.Service;
  using Chiota.Persistence;

  using Tangle.Net.Cryptography.Signing;

  using Windows.Storage;

  /// <summary>
  /// The sql lite contact repository.
  /// </summary>
  public class SqlLiteContactRepository : AbstractSqlLiteContactRepository
  {
    /// <inheritdoc />
    public SqlLiteContactRepository(IMessenger messenger, ISignatureValidator signatureValidator)
      : base(messenger, signatureValidator)
    {
    }

      public override Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
      {
          throw new System.NotImplementedException();
      }

      public override Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
      {
          throw new System.NotImplementedException();
      }
  }
}