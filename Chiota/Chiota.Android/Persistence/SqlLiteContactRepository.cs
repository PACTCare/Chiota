namespace Chiota.Droid.Persistence
{
  using System;
  using System.IO;

  using Chiota.Persistence;

  using Pact.Palantir.Service;

  using SQLite;

  using Tangle.Net.Cryptography.Signing;

  public class SqlLiteContactRepository : AbstractSqlLiteContactRepository
  {
    /// <inheritdoc />
    public SqlLiteContactRepository(IMessenger messenger, ISignatureValidator signatureValidator)
      : base(messenger, signatureValidator)
    {
    }

    /// <inheritdoc />
    public override SQLiteAsyncConnection Connection
    {
      get
      {
        var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var path = Path.Combine(documentsPath, "ChiotaSQLite.db3");

        return new SQLiteAsyncConnection(path);
      }
    }
  }
}