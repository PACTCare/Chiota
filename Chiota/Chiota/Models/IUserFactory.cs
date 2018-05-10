namespace Chiota.Models
{
  using System.Collections.Generic;

  using Tangle.Net.Entity;

  public interface IUserFactory
  {
    User Create(Seed storeSeed, List<Address> addresses);
  }
}