namespace Chiota.IOTAServices
{
  using System.Collections.Generic;

  using RestSharp;

  using Tangle.Net.ProofOfWork;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.Client;

  public class RepositoryFactory
  {
    private readonly List<string> nodeUriList = new List<string>
                                                  {
                                                    "https://trinity.iota.fm:443", // pow test 6 seconds
                                                    "https://nodes.testnet.iota.org:443/", // pow test 8 seconds
                                                    "https://iotanode.us:443", // pow test 10 seconds
                                                    "https://field.carriota.com:443", // pow test 13 seconds
                                                    "https://iri2.iota.fm:443" // pow test 16 seconds
                                                  };

    public RestIotaRepository Create(bool remote = true)
    {
      var iotaClient = new RestIotaClient(new RestClient("https://nodes.iota.fm:443")); // pow test 3 seconds

      var node = GenerateNode(remote, iotaClient);

      if (NoteIsHealthy(node))
      {
        return node;
      }

      foreach (var nodeUri in this.nodeUriList)
      {
        node = GenerateNode(remote, new RestIotaClient(new RestClient(nodeUri)));
        if (NoteIsHealthy(node))
        {
          break;
        }
      }

      return node;
    }

    private static RestIotaRepository GenerateNode(bool remote, IIotaClient iotaClient)
    {
      return remote ? new RestIotaRepository(iotaClient, new RestPoWService(iotaClient)) : new RestIotaRepository(iotaClient, new PoWService(new CpuPowDiver()));
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
