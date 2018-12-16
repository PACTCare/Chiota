#region References

using System.IO;
using System.Threading.Tasks;
using Ipfs.Api;
using Ipfs.CoreApi;

#endregion

namespace Chiota.Services.Ipfs
{
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

        public async Task<Stream> GetFileAsync(string hash)
        {
            var stream = await ipfs.FileSystem.ReadFileAsync(hash);
            return stream;
        }

        public async Task<string> PostFileAsync(string path)
        {
            var addFileOptions = new AddFileOptions { Pin = true };
            var nodeInfo = await ipfs.FileSystem.AddFileAsync(path, addFileOptions);
            return nodeInfo.Id.Hash.ToString();
        }

        public async Task<string> PostStringAsync(string input)
        {
            var addFileOptions = new AddFileOptions { Pin = true };
            var nodeInfo = await ipfs.FileSystem.AddTextAsync(input, addFileOptions);
            return nodeInfo.Id.Hash.ToString();
        }

        public async Task<string> GetStringAsync(string hash)
        {
            var result = await ipfs.FileSystem.ReadAllTextAsync(hash);
            return result;
        }
    }
}
