namespace Chiota.Droid.Persistence
{
  using System;
  using System.IO;

  using Chiota.Persistence;

  using SQLite;

  public class SqlLiteTransactionCache : AbstractSqlLiteTransactionCache
  {
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