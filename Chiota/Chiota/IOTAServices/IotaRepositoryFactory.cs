namespace Chiota.IOTAServices
{
  using System.Collections.Generic;

  using RestSharp;

  using Tangle.Net.ProofOfWork;
  using Tangle.Net.Repository;

  public class IotaRepositoryFactory : IIotaRepositoryFactory
  {
    private readonly List<string> nodeUriList = new List<string>
                                                  {
                                                    "http://node.lukaseder.de:14265",
                                                    "https://iotanode.us:443",
                                                    "http://node05.iotatoken.nl:16265",
                                                    "http://iotahos.tk:14265",
                                                    "http://node02.iotatoken.nl:14265",
                                                    "http://node04.iotatoken.nl:14265",
                                                    "http://node03.iotatoken.nl:14265",
                                                    "http://node01.iotatoken.nl:14265",
                                                    "http://176.9.3.149:14265",
                                                    "http://5.9.149.169:14265",
                                                    "http://5.9.118.112:14265",
                                                    "http://5.9.137.199:14265",
                                                    "http://88.198.230.98:14265",
                                                    "https://beta.tangle-nodes.com:443",
                                                    "https://alpha.tangle-nodes.com:443",
                                                    "https://nodes.iota.cafe:443",
                                                    "https://nodes.thetangle.org:443",
                                                    "http://iota.love:16000",
                                                    "http://nelson1.iota.fm:80",
                                                    "http://iota-tangle.io:14265",
                                                    "http://node.iota.bar:14265",
                                                    "http://tanglelove.com:14265",
                                                    "http://iota.teamveno.eu:14265",
                                                    "http://nodes.iota.fm:80",
                                                    "https://tuna.iotasalad.org:14265",
                                                    "https://durian.iotasalad.org:14265",
                                                    "https://peanut.iotasalad.org:14265",
                                                    "http://iota1.heidger.eu:14265",
                                                    "https://potato.iotasalad.org:14265",
                                                    "http://astra2261.startdedicated.net:14265",
                                                    "http://iotanode.party:14265"
                                                  };

    public RestIotaRepository Create()
    {
      var powService = new PoWService(new CpuPowDiver());
      var node = new RestIotaRepository(new RestClient("https://field.carriota.com:443"), powService);
      if (NoteIsHealthy(node))
      {
        return node;
      }

      foreach (var nodeUri in this.nodeUriList)
      {
        node = new RestIotaRepository(new RestClient(nodeUri), powService);
        if (NoteIsHealthy(node))
        {
          break;
        }
      }

      return node;
    }

    private static bool NoteIsHealthy(IIotaNodeRepository node)
    {
      try
      {
        var nodeInfo = node.GetNodeInfo();
        return nodeInfo.LatestMilestoneIndex == nodeInfo.LatestSolidSubtangleMilestoneIndex;
      }
      catch
      {
        return false;
      }
    }
  }
}
