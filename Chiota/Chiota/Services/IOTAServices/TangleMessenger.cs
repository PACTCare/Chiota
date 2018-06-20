namespace Chiota.Services.IOTAServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Models.SqLite;
  using Chiota.Services;

  using Newtonsoft.Json;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Utils;

  public class TangleMessenger
  {
    private readonly Seed seed;

    private readonly SqLiteHelper sqLite;

    private IIotaRepository repository;

    public TangleMessenger(Seed seed)
    {
      this.seed = seed;

      this.repository = new RepositoryFactory().Create();
      this.ShortStorageAddressList = new List<string>();
      this.sqLite = new SqLiteHelper();
    }

    public List<string> ShortStorageAddressList { get; set; }

    public async Task<bool> SendMessageAsync(TryteString message, string address, int retryNumber = 3)
    {
      var roundNumber = 0;
      while (roundNumber < retryNumber)
      {
        this.UpdateNode(roundNumber);

        var bundle = new Bundle();
        bundle.AddTransfer(CreateTransfer(message, address));

        try
        {
          await this.repository.SendTransferAsync(this.seed, bundle, SecurityLevel.Medium, 27);
          return true;
        }
        catch
        {
          roundNumber++;
        }
      }

      return false;
    }

    public async Task<List<TryteStringMessage>> GetMessagesAsync(string addresse, int retryNumber = 1, bool getChatMessages = false, bool dontLoadSql = false)
    {
      var roundNumber = 0;
      var messagesList = new List<TryteStringMessage>();
      var tableList = new List<SqLiteMessage>();
      var shortStorageHashes = new List<Hash>();

      try
      {
        if (!dontLoadSql)
        {
          tableList = await this.sqLite.LoadTransactions(addresse);

          var alreadyLoaded = this.AddressLoadedCheck(addresse);
          foreach (var sqlLiteMessage in tableList)
          {
            shortStorageHashes.Add(new Hash(sqlLiteMessage.TransactionHash));
            var message = new TryteStringMessage
                            {
                              Message = new TryteString(sqlLiteMessage.MessageTryteString),
                              Stored = true
                            };
            if (!alreadyLoaded)
            {
              messagesList.Add(message);
            }
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
            await this.sqLite.SaveTransaction(addresse, transactionsHash, message.Message.ToString());
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
        var tableList = await this.sqLite.LoadTransactions(addresse);
        var alreadyLoaded = this.AddressLoadedCheck(addresse);

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
              await this.sqLite.SaveTransaction(addresse, transactionsHash, message);
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

    private static Transfer CreateTransfer(TryteString message, string address)
    {
      return new Transfer
               {
                 Address = new Address(address),
                 Message = message,
                 Tag = new Tag(ChiotaConstants.Tag),
                 Timestamp = Timestamp.UnixSecondsTimestamp
               };
    }

    private bool AddressLoadedCheck(string addresse)
    {
      var alreadyLoaded = this.ShortStorageAddressList.Contains(addresse);
      if (!alreadyLoaded)
      {
        this.ShortStorageAddressList.Add(addresse);
      }

      return alreadyLoaded;
    }

    private async Task<List<Hash>> GetNewHashes(string addresse, List<Hash> shortStorageHashes)
    {
      var addresses = new List<Address> { new Address(addresse) };
      var transactions = await this.repository.FindTransactionsByAddressesAsync(addresses);
      return IotaHelper.FilterNewHashes(transactions, shortStorageHashes);
    }

    private void UpdateNode(int roundNumber)
    {
      if (roundNumber > 0)
      {
        this.repository = new RepositoryFactory().Create(roundNumber);
      }
    }
  }
}