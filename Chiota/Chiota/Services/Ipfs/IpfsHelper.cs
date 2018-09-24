namespace Chiota.Services.Ipfs
{
  using System.Threading.Tasks;

  using global::Ipfs.Api;
  using global::Ipfs.CoreApi;

  public class IpfsHelper
  {
    private readonly IpfsClient ipfs;

    public IpfsHelper(string host = "https://ipfsnode.de:5002/") // https://ipfs.infura.io:5001 , https://ipfsnode.de:5002/, 
    {
      ipfs = new IpfsClient(host);
    }

    public async Task<string> CatString(string qmName)
    {
      return await ipfs.FileSystem.ReadAllTextAsync(qmName);
    }

    public async Task<string> PinFile(string path)
    {
      var addFileOptions = new AddFileOptions { Pin = true };
      var nodeInfo = await ipfs.FileSystem.AddFileAsync(path, addFileOptions);
      return nodeInfo.Id.Hash.ToString();
    }

    public async Task<string> PinString(string input)
    {
      var addFileOptions = new AddFileOptions { Pin = true };
      var nodeInfo = await ipfs.FileSystem.AddTextAsync(input, addFileOptions);
      return nodeInfo.Id.Hash.ToString();
    }
  }
}
