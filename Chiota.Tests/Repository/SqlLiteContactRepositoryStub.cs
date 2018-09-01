namespace Chiota.Tests.Repository
{
  using Chiota.Persistence;

  using SQLite;

  using Tangle.Net.Repository;

  public class SqlLiteContactRepositoryStub : AbstractSqlLiteContactRepository
    {
      /// <inheritdoc />
      public SqlLiteContactRepositoryStub(IIotaRepository iotaRepository)
        : base(iotaRepository)
      {
      }

      /// <inheritdoc />
      public override SQLiteAsyncConnection Connection { get; }
    }
}
