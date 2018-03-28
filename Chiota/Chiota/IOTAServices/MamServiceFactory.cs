namespace Chiota.IOTAServices
{
  using Tangle.Net.Entity;
  using Tangle.Net.Mam.Services;

  public class MamServiceFactory
  {
    public MamService Create(Seed seed)
    {
      var repositoryByNodeSelector = new IotaRepositoryFactory();

      // var iotaRepository = new RestIotaRepositoryFactory().CreateAsync().Result;
      return new MamService(repositoryByNodeSelector.Create(), new CurlMask(), seed);
    }
  }
}
