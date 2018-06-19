namespace Chiota.Services.UserServices
{
  using System.Threading.Tasks;

  using Chiota.Models;

  public interface IUserFactory
  {
    Task<User> Create(string seedInput, bool storeSeed);
  }
}