namespace Chiota.Tests.Repository
{
  using Chiota.Messenger.Service;
  using Chiota.Persistence;

  using SQLite;

  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Repository;

  public class SqlLiteContactRepositoryStub : AbstractSqlLiteContactRepository
    {
      /// <inheritdoc />
      public SqlLiteContactRepositoryStub(IMessenger messenger)
        : base(messenger, new SignatureValidator())
      {
      }

      /// <inheritdoc />
      public override SQLiteAsyncConnection Connection { get; }
    }
}
