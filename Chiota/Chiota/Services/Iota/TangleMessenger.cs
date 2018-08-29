namespace Chiota.Services.Iota
{
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Comparison;
  using Chiota.Messenger.Entity;
  using Chiota.Models;
  using Chiota.Models.SqLite;
  using Chiota.Persistence;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Iota.Repository;

  using Newtonsoft.Json;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.DataTransfer;
  using Tangle.Net.Utils;

  public class TangleMessenger
  {
    private const int Depth = 8;

    private readonly Seed seed;

    private readonly SqLiteHelper sqLite;

    private IIotaRepository repository;

    public TangleMessenger(Seed seed, int minWeightMagnitude = 14)
    {
      this.seed = seed;
      this.MinWeight = minWeightMagnitude;
      this.repository = DependencyResolver.Resolve<IRepositoryFactory>().Create();
      this.ShortStorageAddressList = new List<string>();
      this.sqLite = new SqLiteHelper();
    }

    public List<string> ShortStorageAddressList { get; set; }

    private int MinWeight { get; }

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
          await this.repository.SendTransferAsync(this.seed, bundle, SecurityLevel.Medium, Depth, this.MinWeight);
          return true;
        }
        catch (Exception e)
        {
          Trace.WriteLine(e);
          roundNumber++;
        }
      }

      return false;
    }

    public async Task<List<TryteStringMessage>> GetMessagesAsync(string addresse, int retryNumber = 1, bool getChatMessages = false, bool dontLoadSql = false, bool alwaysLoadSql = false)
    {
      var roundNumber = 0;
      var messagesList = new List<TryteStringMessage>();
      var sqlTable = new List<SqLiteMessage>();
      var shortStorageHashes = new List<Hash>();

      if (!dontLoadSql)
      {
        sqlTable = await this.sqLite.LoadTransactionsByAddress(addresse);

        var alreadyLoaded = this.AddressLoadedCheck(addresse);
        foreach (var sqlLiteMessage in sqlTable)
        {
          shortStorageHashes.Add(new Hash(sqlLiteMessage.TransactionHash));
          if (!alreadyLoaded || alwaysLoadSql)
          {
            messagesList.Add(new TryteStringMessage
                               {
                                 Message = new TryteString(sqlLiteMessage.MessageTryteString),
                                 Stored = true
                               });
          }
        }
      }

      // if more than 2*Chiotaconstants.MessagesOnAddress messages on address, don't try to load new messages
      var chatCheck = true;
      if (getChatMessages)
      {
        chatCheck = sqlTable.Count < (2 * ChiotaConstants.MessagesOnAddress);
      }

      while (roundNumber < retryNumber && chatCheck)
      {
        try
        {
          this.UpdateNode(roundNumber);

          var addresses = new List<Address> { new Address(addresse) };
          var transactions = await this.repository.FindTransactionsByAddressesAsync(addresses);
          var hashes = shortStorageHashes.Union(transactions.Hashes, new TryteComparer<Hash>()).ToList();

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

    // Without ShortStorage, always reload contacts
    public async Task<List<Contact>> GetContactsJsonAsync(string address, int retryNumber = 1)
    {
      var contacts = new List<Contact>();
      var cachedTransactionHashes = new List<Hash>();

      var sqlTable = await this.sqLite.LoadTransactionsByAddress(address);
      foreach (var sqlLiteMessage in sqlTable)
      {
        cachedTransactionHashes.Add(new Hash(sqlLiteMessage.TransactionHash));
        contacts.Add(JsonConvert.DeserializeObject<Contact>(sqlLiteMessage.MessageTryteString));
      }

      var addresses = new List<Address> { new Address(address) };
      var transactions = await this.repository.FindTransactionsByAddressesAsync(addresses);
      var newHashes = cachedTransactionHashes.Union(transactions.Hashes, new TryteComparer<Hash>()).ToList();

      foreach (var hash in newHashes)
      {
        var bundle = await this.repository.GetBundleAsync(hash);
        var messages = bundle.GetMessages();
        foreach (var message in messages)
        {
          await this.sqLite.SaveTransaction(address, hash, message);
          var deserializedObject = JsonConvert.DeserializeObject<Contact>(message);
          contacts.Add(deserializedObject);
        }
      }

      return contacts;
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

    private void UpdateNode(int roundNumber)
    {
      if (roundNumber > 0)
      {
        this.repository = DependencyResolver.Resolve<IRepositoryFactory>().Create(roundNumber);
      }
    }
  }
}