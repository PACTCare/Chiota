namespace Chiota.Droid.Persistence
{
  using System;
  using System.IO;

  using Chiota.Models.SqLite;
  using Chiota.Persistence;

  using SQLite;

  public class SqlLiteDb : AbstractSqlLiteDb
  {
    public override SQLiteAsyncConnection GetConnection()
    {
      var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
      var path = Path.Combine(documentsPath, "ChiotaSQLite.db3");

      return new SQLiteAsyncConnection(path);
    }
  }
}