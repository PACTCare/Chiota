namespace Chiota.IOTAServices
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Models;

  using Newtonsoft.Json;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Utils;

  public class TangleMessenger
  {
    private readonly IIotaRepository repository;

    private readonly Seed seed;

    public TangleMessenger(Seed seed)
    {
      this.seed = seed;
      this.repository = new RepositoryFactory().Create();
    }

    public async Task SendMessage(TryteString message, string address)
    {
      var bundle = new Bundle();
      bundle.AddTransfer(this.CreateTransfer(message, address));

      await Task.Factory.StartNew(() => this.repository.SendTransfer(this.seed, bundle, SecurityLevel.Medium, 27, 14));
    }

    public async Task SendJsonMessageAsync<T>(SentDataWrapper<T> data, string address)
    {
      var serializeObject = JsonConvert.SerializeObject(data);
      var bundle = new Bundle();
      bundle.AddTransfer(this.CreateTransfer(TryteString.FromAsciiString(serializeObject), address));

      await Task.Factory.StartNew(() => this.repository.SendTransfer(this.seed, bundle, SecurityLevel.Medium, 27, 14));
    }

    public List<TryteString> GetMessages(string adresse)
    {
      // transaction not found
      var adresses = new List<Address> { new Address(adresse) };
      var transactions = this.repository.FindTransactionsByAddresses(adresses);
      var messagesList = new List<TryteString>();
      foreach (var transactionsHash in transactions.Hashes)
      {
        try
        {
          var bundle = this.repository.GetBundle(transactionsHash);
          messagesList.Add(this.GetMessages(bundle));
        }
        catch
        {
          // ignored
        }
      }

      return messagesList;
    }

    public TryteString GetMessages(Bundle bundle)
    {
      var messageTrytes = string.Empty;
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

      if (!messageTrytes.Contains("9ENDEGUTALLESGUT9"))
      {
        return null;
      }

      var index = messageTrytes.IndexOf("9ENDEGUTALLESGUT9", StringComparison.Ordinal);
      return new TryteString(messageTrytes.Substring(0, index));
    }

    public List<T> GetJsonMessage<T>(string adresse)
    {
      var adresses = new List<Address> { new Address(adresse) };
      var transactions = this.repository.FindTransactionsByAddresses(adresses);
      var messagesList = new List<T>();
      foreach (var transactionsHash in transactions.Hashes)
      {
        var bundle = this.repository.GetBundle(transactionsHash);

        var messages = bundle.GetMessages();
        foreach (var message in messages)
        {
          messagesList.Add(JsonConvert.DeserializeObject<T>(message));
        }
      }

      return messagesList;
    }

    private Transfer CreateTransfer(TryteString message, string adress)
    {
      return new Transfer
      {
        Address = new Address(adress),
        Message = message,
        Tag = new Tag("CHIOTAYOURIOTACHATAPP"),
        Timestamp = Timestamp.UnixSecondsTimestamp
      };
    }
  }
}