namespace Chiota.Events
{
  using System;

  using Microsoft.Bot.Connector.DirectLine;

  /// <inheritdoc />
  public class ActivityEventArgs : EventArgs
  {
    /// <summary>
    /// Gets or sets the activity.
    /// </summary>
    public Activity Activity { get; set; }
  }
}