namespace Chiota.Services.Iota.Repository
{
  using System.Collections.Generic;

  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;
  using Chiota.Resources.Settings;

  using Tangle.Net.ProofOfWork;
  using Tangle.Net.ProofOfWork.Service;
  using Tangle.Net.Repository;

  /// <summary>
  /// The repository factory.
  /// </summary>
  public class RepositoryFactory : IRepositoryFactory
  {
    /// <summary>
    /// The node uri list.
    /// </summary>
    private readonly List<string> nodeUriList = new List<string>
                                                  {
                                                    "https://field.deviota.com:443",
                                                    "https://peanut.iotasalad.org:14265",
                                                    "http://node04.iotatoken.nl:14265",
                                                    "http://node05.iotatoken.nl:16265",
                                                    "https://nodes.thetangle.org:443",
                                                    "http://iota1.heidger.eu:14265",
                                                    "https://nodes.iota.cafe:443",
                                                    "https://potato.iotasalad.org:14265",
                                                    "https://durian.iotasalad.org:14265",
                                                    "https://turnip.iotasalad.org:14265",
                                                    "https://nodes.iota.fm:443",
                                                    "https://tuna.iotasalad.org:14265",
                                                    "https://iotanode2.jlld.at:443",
                                                    "https://node.iota.moe:443",
                                                    "https://wallet1.iota.town:443",
                                                    "https://wallet2.iota.town:443",
                                                    "http://node03.iotatoken.nl:15265",
                                                    "https://node.iota-tangle.io:14265",
                                                    "https://pow4.iota.community:443",
                                                    "https://dyn.tangle-nodes.com:443",
                                                    "https://pow5.iota.community:443"
                                                  };

    /// <inheritdoc />
    public RestIotaRepository Create(int roundNumber = 0)
    {
      var appSettings = ApplicationSettings.Load();
      nodeUriList.Insert(0, appSettings.IotaNodeUri);

      var iotaClient = new MessengerIotaClient(nodeUriList);

      return appSettings.DoRemotePoW
               ? new RestIotaRepository(iotaClient, new PoWSrvService())
               : new RestIotaRepository(iotaClient, new PoWService(new CpuPearlDiver()));
    }
  }
}