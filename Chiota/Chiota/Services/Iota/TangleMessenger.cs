namespace Chiota.Services.Iota
{
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
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

    private AbstractSqlLiteTransactionCache TransactionCache { get; }

    private IIotaRepository Repository { get; }

    public TangleMessenger(Seed seed, int minWeightMagnitude = 14)
    {
      this.seed = seed;
      this.MinWeight = minWeightMagnitude;
      this.Repository = DependencyResolver.Resolve<IIotaRepository>();
      this.ShortStorageAddressList = new List<string>();
      this.TransactionCache = DependencyResolver.Resolve<AbstractSqlLiteTransactionCache>();
    }

    public List<string> ShortStorageAddressList { get; set; }

    private int MinWeight { get; }

    public async Task<bool> SendMessageAsync(TryteString message, string address, int retryNumber = 3)
    {
      var roundNumber = 0;
      while (roundNumber < retryNumber)
      {
        //this.UpdateNode(roundNumber);

        var bundle = new Bundle();
        bundle.AddTransfer(CreateTransfer(message, address));

        try
        {
          await this.Repository.SendTransferAsync(this.seed, bundle, SecurityLevel.Medium, Depth, this.MinWeight);
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

    public async Task<List<TryteStringMessage>> GetMessagesAsync(string address, int retryNumber = 1, bool getChatMessages = false, bool dontLoadSql = false, bool alwaysLoadSql = false)
    {
      var messagesList = new List<TryteStringMessage>();
      var cachedHashes = new List<Hash>();

      if (!dontLoadSql)
      {
        var cachedTransactions = await this.TransactionCache.LoadTransactionsByAddressAsync(new Address(address));

        var alreadyLoaded = this.AddressLoadedCheck(address);
        foreach (var cachedTransaction in cachedTransactions)
        {
          cachedHashes.Add(cachedTransaction.TransactionHash);

          if (!alreadyLoaded || alwaysLoadSql)
          {
            messagesList.Add(new TryteStringMessage
            {
              Message = cachedTransaction.TransactionTrytes,
              Stored = true
            });
          }
        }

        // if more or equal to 2 * ChiotaConstants.MessagesOnAddress messages on address, don't try to load new messages
        if (cachedTransactions.Count >= (2 * ChiotaConstants.MessagesOnAddress))
        {
          return messagesList;
        }
      }

      var transactions = await this.Repository.FindTransactionsByAddressesAsync(new List<Address> { new Address(address) });
      var hashes = transactions.Hashes.Union(cachedHashes, new TryteComparer<Hash>()).ToList();

      foreach (var transactionsHash in hashes)
      {
        var bundle = await this.Repository.GetBundleAsync(transactionsHash);
        var message = new TryteStringMessage { Message = IotaHelper.ExtractMessage(bundle), Stored = false };
        await this.TransactionCache.SaveTransactionAsync(
          new TransactionCacheItem { Address = new Address(address), TransactionHash = transactionsHash, TransactionTrytes = message.Message });
        messagesList.Add(message);
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

  }
}