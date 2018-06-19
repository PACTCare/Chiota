namespace Chiota.IOTAServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Iota.Repository;

  using Tangle.Net.Entity;
  using Tangle.Net.Mam.Merkle;
  using Tangle.Net.Mam.Services;
  using Tangle.Net.Repository;

  using Mode = Tangle.Net.Mam.Entity.Mode;

  public class MamService
  {
    private const int SecurityNumber = 2;

    private readonly RestIotaRepository repository;

    public MamService()
    {
      this.repository = DependencyResolver.Resolve<IRepositoryFactory>().Create();

      this.SubscriptionFactory = new MamChannelSubscriptionFactory(this.repository, CurlMamParser.Default, CurlMask.Default);
      this.ChannelFactory = new MamChannelFactory(CurlMamFactory.Default, CurlMerkleTreeFactory.Default, this.repository);
    }

    private MamChannelFactory ChannelFactory { get; }

    private MamChannelSubscriptionFactory SubscriptionFactory { get; }

    public async Task<Hash> SendMessageAsync(Seed seed, TryteString channelKey, TryteString tyteText)
    {
      var channel = this.ChannelFactory.Create(Mode.Restricted, seed, SecurityNumber, channelKey);

      var message = channel.CreateMessage(tyteText);

      await channel.PublishAsync(message);

      return message.Root;
    }

    public async Task<List<TryteString>> ReceiveMessage(Hash root) // , TryteString channelKey
    {
      var messageList = new List<TryteString>();

      var channelSubscription = this.SubscriptionFactory.Create(root, Mode.Restricted); // , channelKey

      var publishedMessages = await channelSubscription.FetchAsync();

      foreach (var publishedMessage in publishedMessages)
      {
        messageList.Add(publishedMessage.Message);
      }

      return messageList;
    }
  }
}
