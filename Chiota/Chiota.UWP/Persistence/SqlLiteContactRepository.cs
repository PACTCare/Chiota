namespace Chiota.UWP.Persistence
{
  using System.IO;

  using Chiota.Persistence;

  using SQLite;

  using Windows.Storage;

  using Tangle.Net.Repository;

  public class SqlLiteContactRepository : AbstractSqlLiteContactRepository
  {

    /// <inheritdoc />
    public SqlLiteContactRepository(IIotaRepository iotaRepository)
      : base(iotaRepository)
    {
    }

    public override SQLiteAsyncConnection GetConnection()
    {
      var documentsPath = ApplicationData.Current.LocalFolder.Path;
      var path = Path.Combine(documentsPath, "ChiotaSQLite.db3");
      return new SQLiteAsyncConnection(path);
    }
  }
}
