namespace Chiota.Messenger.Entity
{
  using Tangle.Net.Entity;

  public class Message
  {
    public Message(TryteString payload, Address receiver = null)
    {
      this.Payload = payload;
      this.Receiver = receiver;
    }

    public TryteString Payload { get; }

    public Address Receiver { get; }
  }
}