namespace Chiota.IOTAServices
{
  using RestSharp;

  using Tangle.Net.ProofOfWork;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.Client;

  public class RepositoryFactory
  {
    public RestIotaRepository Create(bool remote = true)
    {
      // user carriota or tangle messenger factory
      var iotaClient = new RestIotaClient(new RestClient("https://field.carriota.com:443"));

      // remote or local PoW
      return remote ? new RestIotaRepository(iotaClient, new RestPoWService(iotaClient)) : new RestIotaRepository(iotaClient, new PoWService(new CpuPowDiver()));
    }

  }
}
