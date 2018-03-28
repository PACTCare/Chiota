namespace Chiota.Models
{
  public class SentDataWrapper<T>
  {
    public T Data { get; set; }

    public string Sender { get; set; }

    public string Type => typeof(T).Name;
  }
}