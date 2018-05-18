namespace Chiota.IOTAServices
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using RestSharp;

  using Tangle.Net.Cryptography.Curl;
  using Tangle.Net.ProofOfWork;
  using Tangle.Net.ProofOfWork.HammingNonce;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.Client;

  public class RepositoryFactory
  {
    private const int WaitSeconds = 5;

    private readonly List<string> nodeUriList = new List<string>
                                                  {  
                                                    "https://field.carriota.com:443", 
                                                    "https://nodes.iota.fm:443",  
                                                    "https://trinity.iota.fm:443", 
                                                    "https://nodes.testnet.iota.org:443/", 
                                                    "https://iotanode.us:443", 
                                                    "https://iri2.iota.fm:443" 
                                                  };

    public RestIotaRepository Create(bool remote, int roundNumber = 0, bool bit64 = false)
    {
      var iotaClient = new RestIotaClient(new RestClient(this.nodeUriList[roundNumber])); 

      var node = GenerateNode(remote, iotaClient, bit64);

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

    private static RestIotaRepository GenerateNode(bool remote, IIotaClient iotaClient, bool bit64 = false)
    {
      if (bit64)
      {
        return remote ? new RestIotaRepository(iotaClient, new RestPoWService(iotaClient)) : new RestIotaRepository(iotaClient, new PoWService(new HammingNonceDiver(CurlMode.CurlP27, Mode._64bit)));
      }
      else
      {
        return remote ? new RestIotaRepository(iotaClient, new RestPoWService(iotaClient)) : new RestIotaRepository(iotaClient, new PoWService(new CpuPearlDiver()));
      }
    }

    private static bool NoteIsHealthy(IIotaNodeRepository node)
    {
      try
      {
        // Timeout after 5 seconds
        var task = Task.Run(() => node.GetNodeInfo());
        if (task.Wait(TimeSpan.FromSeconds(WaitSeconds)))
        {
          var nodeInfo = task.Result;
          return nodeInfo.LatestMilestoneIndex == nodeInfo.LatestSolidSubtangleMilestoneIndex;
        }

        return false;
      }
      catch
      {
        return false;
      }
    }
  }
}
