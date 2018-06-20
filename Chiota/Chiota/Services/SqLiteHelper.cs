namespace Chiota.Services
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Models.SqLite;
  using Chiota.Persistence;
  using Chiota.Services.DependencyInjection;

  using SQLite;

  using Tangle.Net.Entity;

  public class SqLiteHelper
  {
    private readonly SQLiteAsyncConnection connection;

    public SqLiteHelper()
    {
      this.connection = DependencyResolver.Resolve<ISqlLiteDb>().GetConnection();
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

    public async Task<List<Contact>> LoadContacts(string publicKeyAddress)
    {
      var contacts = new List<Contact>();
      var sqLiteContacts = await this.connection.QueryAsync<SqLiteContacts>("SELECT * FROM SqLiteContacts Where PublicKeyAddress = ? ORDER BY Id", publicKeyAddress);
      foreach (var sqLiteContact in sqLiteContacts)
      {
        contacts.Add(new Contact
                       {
                         ChatAddress = sqLiteContact.ChatAddress,
                         Rejected = !sqLiteContact.Accepted
                       });
      }

      return contacts;
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

    public async Task SaveContact(string addresse, bool accepted, string publicKeyAddress)
    {
      var sqLiteContacts = new SqLiteContacts
                             {
                               ChatAddress = addresse,
                               Accepted = accepted,
                               PublicKeyAddress = publicKeyAddress
                             };

      await this.connection.InsertAsync(sqLiteContacts);
    }
  }
}
