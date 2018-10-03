namespace Chiota.Messenger.Cucumber.Models
{
  using Tangle.Net.Entity;

  public class Contact : User
  {
    public Address ChatAddress { get; set; }

    public bool IsApproved { get; set; }

    public Address ChatKeyAddress { get; set; }
  }
}