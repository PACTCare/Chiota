namespace Chiota.Models
{
  using Microsoft.WindowsAzure.Storage.Table;

  public class TrytesEntity : TableEntity
  {
    public TrytesEntity(string transactionsHash, string chatAddress)
    {
      // Goal is that if you know the chataddress, you get all the messages on this address
      this.PartitionKey = chatAddress;
      this.RowKey = transactionsHash;
    }

    public TrytesEntity()
    {

    }

    public string TryteStringMessage { get; set; }
  }
}
