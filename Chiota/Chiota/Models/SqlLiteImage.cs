namespace Chiota.Models
{
  using SQLite;

  public class SqlLiteImage
  {
    [PrimaryKey, AutoIncrement]
    public int Id { get; set; }

    public string ImageUrl { get; set; }
  }
}
