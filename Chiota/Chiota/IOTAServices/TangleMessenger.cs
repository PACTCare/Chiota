namespace Chiota.IOTAServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Persistence;
  using Chiota.Services;

  using Models;

  using Newtonsoft.Json;

  using SQLite;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  public class TangleMessenger
  {
    private const bool RemotePow = true;

    private readonly Seed seed;

    private readonly SQLiteAsyncConnection connection;

    // private readonly TableStorage tableStorage;

    private IIotaRepository repository;

    public TangleMessenger(Seed seed)
    {
      this.seed = seed;
      this.repository = new RepositoryFactory().Create(RemotePow);
      this.ShortStorageAddressList = new List<string>();
      this.connection = DependencyService.Get<ISqlLiteDb>().GetConnection();
      this.connection.CreateTableAsync<SqlLiteMessage>();

      // this.tableStorage = new TableStorage();

      // this.tableStorage.CreateTable();
    }

    public List<string> ShortStorageAddressList { get; set; }

    public async Task<bool> SendMessageAsync(TryteString message, string address, int retryNumber = 3)
    {
      var roundNumber = 0;
      while (roundNumber < retryNumber)
      {
        this.UpdateNode(roundNumber);

        var bundle = new Bundle();
        bundle.AddTransfer(this.CreateTransfer(message, address));

        try
        {
          await this.repository.SendTransferAsync(this.seed, bundle, SecurityLevel.Medium, 27, 14);
          return true;
        }
        catch
        {
          roundNumber++;
        }
      }

      return false;
    }

    public async Task<List<TryteStringMessage>> GetMessagesAsync(string addresse, int retryNumber = 1, bool getChatMessages = false)
    {
      var roundNumber = 0;
      var messagesList = new List<TryteStringMessage>();
      var tableList = new List<SqlLiteMessage>();
      var shortStorageHashes = new List<Hash>();

      try
      {
        tableList = await this.GetStoredTransactions(addresse);
        var alreadyLoaded = this.AddressLoadedChack(addresse);
        foreach (var sqlLiteMessage in tableList)
        {
          shortStorageHashes.Add(new Hash(sqlLiteMessage.TransactionHash));
          var message = new TryteStringMessage { Message = new TryteString(sqlLiteMessage.MessageTryteString), Stored = true };
          if (!alreadyLoaded)
          {
            messagesList.Add(message);
          }
        }
      }
      catch
      {
        // ignored
      }

      // if more than 2*Chiotaconstants.MessagesOnAddress messages on address, don't try to load new messages
      var chatCheck = true;
      if (getChatMessages)
      {
        chatCheck = tableList.Count < (2 * ChiotaConstants.MessagesOnAddress);
      }

      while (roundNumber < retryNumber && chatCheck)
      {
        try
        {
          this.UpdateNode(roundNumber);

          var hashes = await this.GetNewHashes(addresse, shortStorageHashes);

          foreach (var transactionsHash in hashes)
          {
            var bundle = await this.repository.GetBundleAsync(transactionsHash);
            var message = new TryteStringMessage { Message = IotaHelper.ExtractMessage(bundle), Stored = false };
            await this.StoreTransaction(addresse, transactionsHash, message.Message.ToString());
            messagesList.Add(message);
          }

          retryNumber = 0;
        }
        catch
        {
          roundNumber++;
        }
      }

      return messagesList;
    }

    public async Task<List<T>> GetJsonMessageAsync<T>(string addresse, int retryNumber = 1)
    {
      var roundNumber = 0;
      var messagesList = new List<T>();
      var shortStorageHashes = new List<Hash>();

      try
      {
        var tableList = await this.GetStoredTransactions(addresse);
        var alreadyLoaded = this.AddressLoadedChack(addresse);

        foreach (var sqlLiteMessage in tableList)
        {
          shortStorageHashes.Add(new Hash(sqlLiteMessage.TransactionHash));

          if (!alreadyLoaded)
          {
            var deserializedObject = JsonConvert.DeserializeObject<T>(sqlLiteMessage.MessageTryteString);
            messagesList.Add(deserializedObject);
          }
        }
      }
      catch
      {
        // ignored
      }

      while (roundNumber < retryNumber)
      {
        try
        {
          this.UpdateNode(roundNumber);
          var hashes = await this.GetNewHashes(addresse, shortStorageHashes);

          foreach (var transactionsHash in hashes)
          {
            var bundle = await this.repository.GetBundleAsync(transactionsHash);
            var messages = bundle.GetMessages();
            foreach (var message in messages)
            {
              await this.StoreTransaction(addresse, transactionsHash, message);
              var deserializedObject = JsonConvert.DeserializeObject<T>(message);
              messagesList.Add(deserializedObject);
            }
          }

          retryNumber = 0;
        }
        catch
        {
          roundNumber++;
        }
      }

      return messagesList;
    }

    private bool AddressLoadedChack(string addresse)
    {
      var alreadyLoaded = this.ShortStorageAddressList.Contains(addresse);
      if (!alreadyLoaded)
      {
        this.ShortStorageAddressList.Add(addresse);
      }

      return alreadyLoaded;
    }

    private async Task StoreTransaction(string addresse, Hash transactionsHash, string message)
    {
      var sqlLiteMessage = new SqlLiteMessage
      {
        TransactionHash = transactionsHash.ToString(),
        ChatAddress = addresse,
        MessageTryteString = message
      };

      // await this.tableStorage.Insert(sqlLiteMessage);
      await this.connection.InsertAsync(sqlLiteMessage);
    }

    private async Task<List<Hash>> GetNewHashes(string addresse, List<Hash> shortStorageHashes)
    {
      var addresses = new List<Address> { new Address(addresse) };
      var transactions = await this.repository.FindTransactionsByAddressesAsync(addresses);
      return IotaHelper.FilterNewHashes(transactions, shortStorageHashes);
    }

    private async Task<List<SqlLiteMessage>> GetStoredTransactions(string addresse)
    {
      var tableList = await this.connection.QueryAsync<SqlLiteMessage>(
               "SELECT * FROM SqlLiteMessage WHERE ChatAddress = ? ORDER BY Id",
               addresse);

      // means no data found local
      // if (tableList == null || tableList.Count == 0)
      // {
      //  tableList = await this.tableStorage.GetTableContent(addresse);
      // }

      return tableList;
    }

    private void UpdateNode(int roundNumber)
    {
      if (roundNumber > 0)
      {
        this.repository = new RepositoryFactory().Create(RemotePow, roundNumber);
      }
    }

    private Transfer CreateTransfer(TryteString message, string address)
    {
      return new Transfer
      {
        Address = new Address(address),
        Message = message,
        Tag = new Tag(ChiotaConstants.Tag),
        Timestamp = Timestamp.UnixSecondsTimestamp
      };
    }
  }
}