namespace Chiota.IOTAServices
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Models;

  using Newtonsoft.Json;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.DataTransfer;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  public class TangleMessenger
  {
    private const bool RemotePow = true;

    private readonly Seed seed;

    private IIotaRepository repository;

    public TangleMessenger(Seed seed)
    {
      this.ShortStorageHashes = new List<Hash>();
      this.seed = seed;
      this.repository = new RepositoryFactory().Create(RemotePow);
    }

    public List<Hash> ShortStorageHashes { get; set; }

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

    public async Task<List<TryteStringMessage>> GetMessagesAsync(string adresse, int retryNumber = 1, bool returnOnlyNew = true)
    {
      var roundNumber = 0;
      var messagesList = new List<TryteStringMessage>();
      TransactionHashList transactions;

      while (roundNumber < retryNumber)
      {
        try
        {
          this.UpdateNode(roundNumber);
          var adresses = new List<Address> { new Address(adresse) };

          // Todo Change Address, so less transactions to load
          // Store old tranactions hashs
          // this always returns all 
          transactions = await this.repository.FindTransactionsByAddressesAsync(adresses);
          var hashes = transactions.Hashes;
          if (returnOnlyNew)
          {
            hashes = IotaHelper.GetNewHashes(transactions, this.ShortStorageHashes);
          }

          foreach (var transactionsHash in hashes)
          {
            this.ShortStorageHashes.Add(transactionsHash);
            messagesList.Add(await this.MessageFromBundleOrStorage(transactionsHash));
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

    public async Task<List<T>> GetJsonMessageAsync<T>(string adresse, int retryNumber = 1, bool returnOnlyNew = true)
    {
      var roundNumber = 0;
      var messagesList = new List<T>();

      while (roundNumber < retryNumber)
      {
        try
        {
          this.UpdateNode(roundNumber);

          var adresses = new List<Address> { new Address(adresse) };
          var transactions = await this.repository.FindTransactionsByAddressesAsync(adresses);

          var hashes = transactions.Hashes;
          if (returnOnlyNew)
          {
            hashes = IotaHelper.GetNewHashes(transactions, this.ShortStorageHashes);
          }

          foreach (var transactionsHash in hashes)
          {
            this.ShortStorageHashes.Add(transactionsHash);

            var hashString = transactionsHash.ToString();
            if (Application.Current.Properties.ContainsKey(hashString))
            {
              var messageString = Application.Current.Properties[hashString] as string;
              var deserializedObject = JsonConvert.DeserializeObject<T>(messageString);
              messagesList.Add(deserializedObject);
            }
            else
            {
              var bundle = await this.repository.GetBundleAsync(transactionsHash);
              var messages = bundle.GetMessages();
              foreach (var message in messages)
              {
                var deserializedObject = JsonConvert.DeserializeObject<T>(message);
                messagesList.Add(deserializedObject);
                Application.Current.Properties[hashString] = message;
                await Application.Current.SavePropertiesAsync();
              }
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

    private void UpdateNode(int roundNumber)
    {
      if (roundNumber > 0)
      {
        this.repository = new RepositoryFactory().Create(RemotePow, roundNumber);
      }
    }

    private TryteString GetMessages(Bundle bundle)
    {
      var messageTrytes = string.Empty;

      // multiple message per bundle?
      foreach (var transaction in bundle.Transactions)
      {
        if (transaction.Value < 0)
        {
          continue;
        }

        if (!transaction.Fragment.IsEmpty)
        {
          messageTrytes += transaction.Fragment.Value;
        }
      }

      if (!messageTrytes.Contains(ChiotaConstants.End))
      {
        return null;
      }

      var index = messageTrytes.IndexOf(ChiotaConstants.End, StringComparison.Ordinal);
      return new TryteString(messageTrytes.Substring(0, index));
    }

    private async Task<TryteStringMessage> MessageFromBundleOrStorage(Hash transactionsHash)
    {
      // table storage as a backup service for snapshots
      var message = new TryteStringMessage();
      var hashString = transactionsHash.ToString();
      if (Application.Current.Properties.ContainsKey(hashString))
      {
        // old messages
        var messageString = Application.Current.Properties[hashString] as string;
        message.Message = new TryteString(messageString);
        message.Stored = true;
      }
      else
      {
        // new messages
        var bundle = await this.repository.GetBundleAsync(transactionsHash);
        message.Message = this.GetMessages(bundle);
        message.Stored = false;
        Application.Current.Properties[hashString] = message.Message.ToString();
        await Application.Current.SavePropertiesAsync();
      }

      return message;
    }

    private Transfer CreateTransfer(TryteString message, string adress)
    {
      return new Transfer
      {
        Address = new Address(adress),
        Message = message,
        Tag = new Tag(ChiotaConstants.Tag),
        Timestamp = Timestamp.UnixSecondsTimestamp
      };
    }
  }
}