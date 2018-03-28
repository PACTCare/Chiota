namespace Chiota.IOTAServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Mam.Entity;
  using Tangle.Net.Mam.Merkle;
  using Tangle.Net.Mam.Services;
  using Tangle.Net.Repository;

  // https://github.com/Felandil/tangle-.net/blob/master/Tangle.Net/Tangle.Net.Examples/Examples/Mam/MamExample.cs
  public class MamService
  {
    private const int SecurityNumber = 1;

    public MamService(IIotaRepository repository, IMask mask, Seed seed)
    {
      var curl = new Curl();
      var treeFactory = new CurlMerkleTreeFactory(new CurlMerkleNodeFactory(curl), new CurlMerkleLeafFactory(new AddressGenerator(seed, SecurityNumber)));
      var mamFactory = new CurlMamFactory(curl, mask);
      var mamParser = new CurlMamParser(mask, treeFactory, curl);
      this.ChannelFactory = new MamChannelFactory(mamFactory, treeFactory, repository);
      this.SubscriptionFactory = new MamChannelSubscriptionFactory(repository, mamParser);
    }
 
    private MamChannelFactory ChannelFactory { get; }

    private MamChannelSubscriptionFactory SubscriptionFactory { get; }

    public async Task<Hash> SendMessage(Seed seed, TryteString channelKey, TryteString tyteText)
    {
      var channel = this.ChannelFactory.Create(Mode.Restricted, seed, SecurityNumber, channelKey);

      var message = channel.CreateMessage(tyteText);

      await channel.PublishAsync(message);

      return message.Root;
    }

    public async Task<List<TryteString>> ReceiveMessage(Hash root, TryteString channelKey)
    {
      var messageList = new List<TryteString>();
      
      var channelSubscription = this.SubscriptionFactory.Create(root, Mode.Restricted, channelKey, SecurityNumber);

      var publishedMessages = await channelSubscription.FetchAsync();

      foreach (var publishedMessage in publishedMessages)
      {
        messageList.Add(publishedMessage.Message);
      }

      return messageList;
    }



    //public async Task<bool> SendMessageAsync(User user, Contact contact, TryteString message)
      //{
      //  try
      //  {
      //    var addresses = await Task.Factory.StartNew(() => new AddressGenerator(user.Seed)); // without https://github.com/Felandil/tangle-.net/blob/master/Tangle.Net/Tangle.Net.Examples/Examples/Mam/MamExample.cs
      //    var treeFactory = new CurlMerkleTreeFactory(new CurlMerkleNodeFactory(new Curl()), new CurlMerkleLeafFactory(addresses));
      //    var merkleTree = await Task.Factory.StartNew(() => treeFactory.Create(user.Seed, contact.CurrentMessageIndex, 1, SecurityLevel.Medium));
      //    var nextMerkleTree = await Task.Factory.StartNew(() => treeFactory.Create(user.Seed, contact.CurrentMessageIndex + 1, 1, SecurityLevel.Medium));
      //    var nextRootHash = nextMerkleTree.Root.Hash;

      //    var mamFactory = new CurlMamFactory(new Curl(), new CurlMask());

      //    var maskedAuthenticatedMessage = mamFactory.Create(
      //      merkleTree,
      //      contact.CurrentMessageIndex,
      //      message,
      //      nextRootHash,
      //      new TryteString(contact.SendChannelKey));

      //    var tes = maskedAuthenticatedMessage.Payload.Transactions[0].Address.Value;

      //    await Task.Factory.StartNew(() => this.Repository.SendTrytes(maskedAuthenticatedMessage.Payload.Transactions, 27, 14));

      //    contact.CurrentMessageIndex++;
      //    //contact.SendChannelKey = maskedAuthenticatedMessage.NextChannelKey.Value;
      //    return true;
      //  }
      //  catch
      //  {
      //    return false;
      //  }
      //}

      //public async Task<bool> SendJsonMessageAsync<T>(User user, Contact contact, SentDataWrapper<T> jsonMessage)
      //{
      //  var message = TryteString.FromUtf8String(JsonConvert.SerializeObject(jsonMessage));
      //  return await this.SendMessageAsync(user, contact, message);
      //}

      //public List<T> ReceiveMamMessages<T>(string channelKey)
      //{
      //  var jsonList = new List<T>();
      //  var messagesList = this.TraverseMamMessages(channelKey);
      //  foreach (var message in messagesList)
      //  {
      //    jsonList.Add(JsonConvert.DeserializeObject<T>(message.ToUtf8String()));
      //  }

      //  return jsonList;
      //}

      //public List<TryteString> TraverseMamMessages(string userChannelKey)
      //{
      //  var messagesList = new List<TryteString>();
      //  var addressHash = this.Mask.Hash(new TryteString(userChannelKey));
      //  addressHash = this.Mask.Hash(addressHash); 

      //  var transactionHashList = this.Repository.FindTransactionsByAddresses(new List<Address> { new Address(addressHash.Value) });

      //  if (!transactionHashList.Hashes.Any())
      //  {
      //    return messagesList;
      //  }

      //  var bundle = this.Repository.GetBundles(transactionHashList.Hashes, false)[0];
      //  var unmaskedMessage = this.MamParser.Unmask(bundle, new TryteString(userChannelKey), SecurityLevel.Medium);
      //  messagesList.Add(unmaskedMessage.Message);

      //  // messagesList.AddRange(this.TraverseMamMessages(unmaskedMessage.NextChannelKey.Value));
      //  return messagesList;
      //}
    }
}
