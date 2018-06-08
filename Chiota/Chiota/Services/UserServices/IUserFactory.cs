namespace Chiota.Services.UserServices
{
  using System.Collections.Generic;

  using Chiota.Models;

  using Tangle.Net.Entity;

  public interface IUserFactory
  {
    User Create(Seed seed, List<Address> addresses);
  }
}