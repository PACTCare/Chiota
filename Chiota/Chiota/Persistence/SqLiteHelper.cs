namespace Chiota.Persistence
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Models.SqLite;
  using Chiota.Services.DependencyInjection;

  using SQLite;

  using Tangle.Net.Entity;

  public class SqLiteHelper
  {
    private readonly SQLiteAsyncConnection connection;

    public SqLiteHelper()
    {
      this.connection = DependencyResolver.Resolve<AbstractSqlLiteDb>().GetConnection();
      this.connection.CreateTableAsync<SqLiteMessage>();
      this.connection.CreateTableAsync<SqLiteContacts>();
    }

    public async Task<List<SqLiteMessage>> LoadTransactions(string addresse)
    {
      List<SqLiteMessage> test;
      try
      {
        test = await this.connection.QueryAsync<SqLiteMessage>(
                     "SELECT * FROM SqLiteMessage Where ChatAddress = ? ORDER BY Id",
                     addresse);
      }
      catch (Exception e)
      {
        Console.WriteLine(e);
        throw;
      }
      
      return test;
    }

    public async Task SaveTransaction(string addresse, Hash transactionsHash, string message)
    {
      var sqlLiteMessage = new SqLiteMessage
                             {
                               TransactionHash = transactionsHash.ToString(),
                               ChatAddress = addresse,
                               MessageTryteString = message
                             };

      await this.connection.InsertAsync(sqlLiteMessage);
    }
  }
}
