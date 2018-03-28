namespace Chiota.IOTAServices
{
  using Tangle.Net.Repository;

  public interface IIotaRepositoryFactory
  {
    RestIotaRepository Create();
  }
}