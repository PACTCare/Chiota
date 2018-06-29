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
    
    public async Task<string> UploadEncryptedAsync(string name, Stream imageAsStream)
    {
      var imageAsBytes = StreamToByte(imageAsStream);

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

    private static byte[] StreamToByte(Stream input)
    {
      var buffer = new byte[16 * 1024];
      using (var ms = new MemoryStream())
      {
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
          ms.Write(buffer, 0, read);
        }

        return ms.ToArray();
      }
    }
  }
}
