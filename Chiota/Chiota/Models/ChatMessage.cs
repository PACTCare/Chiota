namespace Chiota.Models
{
  using System;

  public class ChatMessage
  {
    public DateTime Date { get; set; }

    public string Message { get; set; }

    public string Signature { get; set; }

    public bool IsFirstPart { get; set; }
  }
}
