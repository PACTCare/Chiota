namespace Chiota.Services.IOTAServices
{
  using System.Collections.Generic;

  using Chiota.Models;

  using RestSharp;

  using Tangle.Net.Cryptography.Curl;
  using Tangle.Net.ProofOfWork;
  using Tangle.Net.ProofOfWork.HammingNonce;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.Client;

  using Xamarin.Forms;

  using Mode = Tangle.Net.ProofOfWork.HammingNonce.Mode;

  public class RepositoryFactory
  {
    private readonly List<string> nodeUriList = new List<string>
                                                  {
                                                    "https://nodes.iota.fm:443",
                                                    "https://trinity.iota.fm:443",
                                                    "https://iotanode.us:443",
                                                    "https://iri2.iota.fm:443",
                                                    "https://field.carriota.com:443"
                                                  };

    public static RestIotaRepository GenerateNode(bool remote, IIotaClient iotaClient, bool bit64 = false)
    {
      if (bit64)
      {
        return remote ? new RestIotaRepository(iotaClient, new RestPoWService(iotaClient)) : new RestIotaRepository(iotaClient, new PoWService(new HammingNonceDiver(CurlMode.CurlP27, Mode._64bit)));
      }

      return remote ? new RestIotaRepository(iotaClient, new RestPoWService(iotaClient)) : new RestIotaRepository(iotaClient, new PoWService(new CpuPearlDiver()));
    }

    public RestIotaRepository Create(int roundNumber = 0, bool bit64 = false)
    {
      this.nodeUriList.Insert(0, Application.Current.Properties[ChiotaConstants.SettingsNodeKey] as string);
      var remoteSettings = Application.Current.Properties[ChiotaConstants.SettingsPowKey] as bool?;
      var remote = remoteSettings == true;
      var iotaClient = new RestIotaClient(new RestClient(this.nodeUriList[roundNumber]));

      var node = GenerateNode(remote, iotaClient, bit64);

      if (NodeTest.NodeIsHealthy(node))
      {
        return node;
      }

      foreach (var nodeUri in this.nodeUriList)
      {
        node = GenerateNode(remote, new RestIotaClient(new RestClient(nodeUri)));
        if (NodeTest.NodeIsHealthy(node))
        {
          break;
        }
      }

      return node;
    }
  }
}
