namespace Chiota.IOTAServices
{
  using Tangle.Net.Entity;

  public class TangleMessengerFactory : ITangleMessengerFactory
  {
    public TangleMessenger Create(Seed seed)
    {
      var repositoryByNodeSelector = new IotaRepositoryFactory();
      return new TangleMessenger(seed, repositoryByNodeSelector.Create());
    }
  }
}