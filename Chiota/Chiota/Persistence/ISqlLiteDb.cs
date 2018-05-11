namespace Chiota.Persistence
{
  using SQLite;

  public interface ISqlLiteDb
  {
    SQLiteAsyncConnection GetConnection();
  }
}
