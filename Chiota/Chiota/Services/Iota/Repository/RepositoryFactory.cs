namespace Chiota.Services.Iota.Repository
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Models;

  using RestSharp;

  using Tangle.Net.ProofOfWork;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.Client;

  using Xamarin.Forms;

  /// <summary>
  /// The repository factory.
  /// </summary>
  public class RepositoryFactory : IRepositoryFactory
  {
    private const int WaitSeconds = 5;

    /// <summary>
    /// The node uri list.
    /// </summary>
    private readonly List<string> nodeUriList = new List<string>
                                                  {
                                                    "https://field.carriota.com:443",
                                                    "https://nodes.iota.fm:443",
                                                    "https://trinity.iota.fm:443",
                                                    "https://iotanode.us:443",
                                                    "https://iri2.iota.fm:443"
                                                  };

    public static RestIotaRepository GenerateNode(bool doRemotePoW, string nodeUri)
    {
      var iotaClient = new RestIotaClient(new RestClient(nodeUri));

      return doRemotePoW
               ? new RestIotaRepository(iotaClient, new RestPoWService(iotaClient))
               : new RestIotaRepository(iotaClient, new PoWService(new CpuPearlDiver()));
    }

    /// <summary>
    /// The node is healthy.
    /// </summary>
    /// <param name="node">
    /// The node.
    /// </param>
    /// <returns>
    /// The <see cref="bool"/>.
    /// </returns>
    public static bool NodeIsHealthy(IIotaNodeRepository node)
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
      }
      catch
      {
        // ignored
      }

      return false;
    }

    /// <inheritdoc />
    public RestIotaRepository Create(int roundNumber = 0)
    {
      this.nodeUriList.Insert(0, Application.Current.Properties[ChiotaConstants.SettingsNodeKey] as string);
      var remoteSettings = Application.Current.Properties[ChiotaConstants.SettingsPowKey] as bool?;
      var remote = remoteSettings == true;

      var node = GenerateNode(remote, this.nodeUriList[roundNumber]);

      if (NodeIsHealthy(node))
      {
        return node;
      }

      foreach (var nodeUri in this.nodeUriList)
      {
        node = GenerateNode(remote, nodeUri);
        if (NodeIsHealthy(node))
        {
          break;
        }
      }

      return node;
    }
  }
}