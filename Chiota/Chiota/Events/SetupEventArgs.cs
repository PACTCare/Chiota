namespace Chiota.Events
{
  using System;

  using Chiota.Models;

  /// <inheritdoc />
  public class SetupEventArgs : EventArgs
  {
    /// <summary>
    /// Gets or sets the user.
    /// </summary>
    public User User { get; set; }
  }
}