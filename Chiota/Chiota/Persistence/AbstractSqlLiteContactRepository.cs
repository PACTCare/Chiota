using Chiota.Models.Database;

namespace Chiota.Persistence
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;

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
    }

  }
}