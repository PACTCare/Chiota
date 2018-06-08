namespace Chiota.UWP.Persistence
{
  using System.IO;

  using Chiota.Persistence;

  using SQLite;

  using Windows.Storage;

  public class SqlLiteDb : ISqlLiteDb
  {
    public SQLiteAsyncConnection GetConnection()
    {
      var documentsPath = ApplicationData.Current.LocalFolder.Path;
      var path = Path.Combine(documentsPath, "ChiotaSQLite.db3");
      return new SQLiteAsyncConnection(path);
    }
  }
}
