namespace Chiota.IOTAServices
{
  using System;
  using System.Threading.Tasks;

  using Tangle.Net.Repository;

  public static class NodeTest
  {
    private const int WaitSeconds = 5;

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

        return false;
      }
      catch
      {
        return false;
      }
    }
  }
}
