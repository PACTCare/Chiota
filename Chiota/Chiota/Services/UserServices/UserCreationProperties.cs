namespace Chiota.Services.UserServices
{
  using Tangle.Net.Entity;

  /// <summary>
  /// The user creation properties.
  /// </summary>
  public class UserCreationProperties
  {
    /// <summary>
    /// Gets or sets the name.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    public string Password { get; set; }

    /// <summary>
    /// Gets or sets the seed.
    /// </summary>
    public Seed Seed { get; set; }
  }
}