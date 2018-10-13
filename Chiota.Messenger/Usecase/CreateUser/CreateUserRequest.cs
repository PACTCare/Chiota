namespace Chiota.Messenger.Usecase.CreateUser
{
  using Tangle.Net.Entity;

  public class CreateUserRequest
  {
    /// <summary>
    /// The seed associated with the user. User data will be derived from the seed.
    /// </summary>
    public Seed Seed { get; set; }
  }
}