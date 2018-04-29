namespace Chiota.Services
{
  using Chiota.Models;

  using Microsoft.WindowsAzure.Storage;
  using Microsoft.WindowsAzure.Storage.Table;

  // https://docs.microsoft.com/de-de/azure/cosmos-db/table-storage-how-to-use-dotnet
  // Used to store data for snapshots
  public class TableStorage
  {
    private const string ConnectionString = ""; // <= Put your table storage string here

    // suggestions to use tag name as table name
    private const string TableName = "CHIOTAYOURIOTACHATAPP";

    public bool CreateTable()
    {
      try
      {
        // Retrieve the storage account from the connection string.
        var storageAccount = CloudStorageAccount.Parse(ConnectionString);

        // Create the table client.
        var tableClient = storageAccount.CreateCloudTableClient();

        // Retrieve a reference to the table.
        var table = tableClient.GetTableReference(TableName);

        // Create the table if it doesn't exist.
        table.CreateIfNotExistsAsync();
        return true;
      }
      catch
      {
        return false;
      }
    }

    public bool Insert(TrytesEntity entity)
    {
      try
      {
        // Retrieve the storage account from the connection string.
        var storageAccount = CloudStorageAccount.Parse(ConnectionString);

        // Create the table client.
        var tableClient = storageAccount.CreateCloudTableClient();

        // Create the CloudTable object that represents the "people" table.
        var table = tableClient.GetTableReference(TableName);

        // Create the TableOperation object that inserts the customer entity.
        var insertOperation = TableOperation.Insert(entity);

        // Execute the insert operation.
        table.ExecuteAsync(insertOperation);
        return true;
      }
      catch
      {
        return false;
      }
    }

    public TableQuery<TrytesEntity> GeTrytesEntities(string address)
    {
      // Retrieve the storage account from the connection string.
      var storageAccount = CloudStorageAccount.Parse(ConnectionString);

      // Create the table client.
      var tableClient = storageAccount.CreateCloudTableClient();

      // Create the CloudTable object that represents the "people" table.
      var table = tableClient.GetTableReference(TableName);

      // Construct the query operation for all customer entities where PartitionKey="Smith".
      var query = new TableQuery<TrytesEntity>().Where(TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, address));

      return query;
    }
  }
}
