namespace Chiota.IOTAServices
{
  using Chiota.Services;

  using Tangle.Net.Entity;

  public interface ITangleMessengerFactory
  {
    TangleMessenger Create(Seed seed);
  }
}