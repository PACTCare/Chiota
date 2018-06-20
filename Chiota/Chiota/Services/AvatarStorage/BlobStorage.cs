namespace Chiota.Services.AvatarStorage
{
  using System.IO;
  using System.Threading.Tasks;

  using Chiota.Models;

  using Microsoft.WindowsAzure.Storage;
  using Microsoft.WindowsAzure.Storage.Blob;

  public class BlobStorage : IAvatarStorage
  {
    private readonly CloudBlobClient blobClient;

    public BlobStorage()
    {
      var storageAccount = CloudStorageAccount.Parse(""); // <-Input Blog Storage Key
      this.blobClient = storageAccount.CreateCloudBlobClient();
    }

    public async Task<string> UploadEncryptedAsync(string name, byte[] imageAsBytes)
    {
      // Retrieve reference to a previously created container.
      var container = this.blobClient.GetContainerReference("userimages");
      var fileName = name + "." + "jpg";

      // Retrieve reference to a blob named "myblob".
      var blockBlob = container.GetBlockBlobReference(fileName);
      blockBlob.Properties.ContentType = "image/jpg";

      // Create or overwrite the "myblob" blob with contents from a local file.
      using (var stream = new MemoryStream(imageAsBytes, false))
      {
        await blockBlob.UploadFromStreamAsync(stream);
      }

      return ChiotaConstants.ImagePath + fileName;
    }
  }
}
