namespace Chiota.Events
{
  using System;

  using Chiota.Models;

  /// <summary>
  /// The login event args.
  /// </summary>
  public class LoginEventArgs : EventArgs
  {
    /// <summary>
    /// Gets or sets the user.
    /// </summary>
    public User User { get; set; }
  }
}