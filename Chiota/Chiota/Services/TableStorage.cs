namespace Chiota.Services
{
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.Threading.Tasks;

  using Chiota.Models;

  using Microsoft.WindowsAzure.Storage;
  using Microsoft.WindowsAzure.Storage.Table;

  // https://docs.microsoft.com/de-de/azure/cosmos-db/table-storage-how-to-use-dotnet
  // Used to store data for snapshots
  public class TableStorage
  {
    // suggestions to use tag name as table name
    private const string TableName = "chiotayourchatapp";

    private readonly CloudStorageAccount storageAccount;

    public TableStorage()
    {
      // Retrieve the storage account from the connection string.
      this.storageAccount = CloudStorageAccount.Parse(""); // <= Put your table storage string here
    }

    public async Task<bool> CreateTable()
    {
      try
      {
        // Create the table client.
        var tableClient = this.storageAccount.CreateCloudTableClient();

        // Retrieve a reference to the table.
        var table = tableClient.GetTableReference(TableName);

        // Create the table if it doesn't exist.
        await table.CreateIfNotExistsAsync();

        return true;
      }
      catch (StorageException e)
      {
        Trace.WriteLine(e);
        return false;
      }
    }

    public async Task<bool> Insert(SqlLiteMessage sqlLiteMessage)
    {
      try
      {
        // Create the table client.
        var tableClient = this.storageAccount.CreateCloudTableClient();

        // Create the CloudTable object that represents the "people" table.
        var table = tableClient.GetTableReference(TableName);

        // Create the TableOperation object that inserts the customer entity.
        var insertOperation = TableOperation.Insert(new TrytesEntity
                                                      {
                                                        RowKey = sqlLiteMessage.TransactionHash,
                                                        PartitionKey = sqlLiteMessage.ChatAddress,
                                                        MessageTryteString = sqlLiteMessage.MessageTryteString
                                                      });

        // Execute the insert operation.
        await table.ExecuteAsync(insertOperation);
        return true;
      }
      catch
      {
        return false;
      }
    }

    public async Task<List<SqlLiteMessage>> GetTableContent(string address)
    {
      var tableList = new List<SqlLiteMessage>();

      // Create the table client.
      var tableClient = this.storageAccount.CreateCloudTableClient();

      // Create the CloudTable object that represents the "people" table.
      var table = tableClient.GetTableReference(TableName);

      // Construct the query operation for all customer entities where PartitionKey="Smith".
      var query = new TableQuery<TrytesEntity>().Where(
        TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, address));

      // Print the fields for each customer.
      TableContinuationToken token = null;
      do
      {
        var resultSegment = await table.ExecuteQuerySegmentedAsync(query, token);
        token = resultSegment.ContinuationToken;

        foreach (var entity in resultSegment.Results)
        {
          tableList.Add(new SqlLiteMessage
                          {
                            TransactionHash = entity.RowKey,
                            MessageTryteString = entity.MessageTryteString,
                            ChatAddress = entity.PartitionKey
                          });
        }
      }
      while (token != null);

      return tableList;
    }
  }
}
