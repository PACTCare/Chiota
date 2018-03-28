namespace Chiota.Services
{
  using System.IO;
  using System.Threading.Tasks;

  using Microsoft.WindowsAzure.Storage;
  using Microsoft.WindowsAzure.Storage.Blob;

  public class BlobStorage
  {
    private readonly CloudBlobClient blobClient;

    public BlobStorage()
    {
      var storageAccount = CloudStorageAccount.Parse("");// <-Input Blog Storage Key
      this.blobClient = storageAccount.CreateCloudBlobClient();
    }

    public async Task<string> UploadToBlob(string adressString, string path)
    {
      // Retrieve reference to a previously created container.
      var container = this.blobClient.GetContainerReference("userimages");

      var imageType = path.Split('.');

      var fileName = adressString + "." + imageType[imageType.Length - 1];

      // Retrieve reference to a blob named "myblob".
      var blockBlob = container.GetBlockBlobReference(fileName);

      blockBlob.Properties.ContentType = "image/" + imageType[imageType.Length - 1];

      // Create or overwrite the "myblob" blob with contents from a local file.
      using (var fileStream = File.OpenRead(path))
      {
        await blockBlob.UploadFromStreamAsync(fileStream);
      }

      return "https://chiota.blob.core.windows.net/userimages/" + fileName;
    }
  }
}
