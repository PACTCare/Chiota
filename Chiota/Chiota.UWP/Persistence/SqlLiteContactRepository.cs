namespace Chiota.UWP.Persistence
{
  using System.IO;

  using Chiota.Persistence;

  using SQLite;

  using Tangle.Net.Repository;

  using Windows.Storage;

  using Tangle.Net.Cryptography.Signing;

  /// <summary>
  /// The sql lite contact repository.
  /// </summary>
  public class SqlLiteContactRepository : AbstractSqlLiteContactRepository
  {
    /// <inheritdoc />
    public SqlLiteContactRepository(IIotaRepository iotaRepository, ISignatureValidator signatureValidator)
      : base(iotaRepository, signatureValidator)
    {
    }

    /// <summary>
    /// Gets the connection.
    /// </summary>
    public override SQLiteAsyncConnection Connection
    {
      get
      {
        var documentsPath = ApplicationData.Current.LocalFolder.Path;
        var path = Path.Combine(documentsPath, "ChiotaSQLite.db3");
        return new SQLiteAsyncConnection(path);
      }
    }
  }
}