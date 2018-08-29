namespace Chiota.UWP.Persistence
{
  using System.IO;

  using Chiota.Persistence;

  using SQLite;

  using Windows.Storage;

  /// <summary>
  /// The sql lite transaction cache.
  /// </summary>
  public class SqlLiteTransactionCache : AbstractSqlLiteTransactionCache
  {
    /// <inheritdoc />
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