//namespace Chiota.Services.Ipfs
//{
//  using System;
//  using System.Diagnostics;
//  using System.IO;
//  using System.Linq;
//  using System.Threading.Tasks;

//  using global::Ipfs;
//  using global::Ipfs.Engine;

//  public class IpfsHelper
//  {
//    private readonly IpfsEngine ipfsEngine;

//    public IpfsHelper(string passphrase)
//    {
//      this.ipfsEngine = new IpfsEngine(passphrase.ToCharArray());
//      var testpath = Path.GetTempPath();
//      this.ipfsEngine.Options.Repository.Folder = Path.Combine(testpath, "ipfs-test");
//      this.ipfsEngine.Options.KeyChain.DefaultKeySize = 512;
//    }

//    public async Task StartEngine()
//    {
//      await this.ipfsEngine.StartAsync();
//    }

//    public async Task StopEngine()
//    {
//      await this.ipfsEngine.StopAsync();
//    }

//    public async Task<string> StoreText(string text)
//    {
//      IFileSystemNode data = null;
//      try
//      {
//        data = await this.ipfsEngine.FileSystem.AddTextAsync(text);
//      }
//      catch (Exception e)
//      {
//        Trace.WriteLine(e);
//      }

//      await this.ipfsEngine.StopAsync();
//      return data?.Id.Hash.ToString();
//    }

//    //public async Task GetFile()
//    //{

//    //}


//    public async Task SeePeers()
//    {
//      var bootPeers = (await this.ipfsEngine.Bootstrap.ListAsync()).ToArray();
//      await this.ipfsEngine.StartAsync();
//      try
//      {
//        var swarm = await this.ipfsEngine.SwarmService;
//        var knownPeers = swarm.KnownPeerAddresses.ToArray();
//        while (bootPeers.Count() != knownPeers.Count())
//        {
//          await Task.Delay(50);
//          knownPeers = swarm.KnownPeerAddresses.ToArray();
//        }
//      }
//      finally
//      {
//        await this.ipfsEngine.StopAsync();
//      }
//    }

//    public async Task Test()
//    {
//      await this.ipfsEngine.StartAsync();
//      try
//      {
//        var data = await this.ipfsEngine.FileSystem.AddTextAsync("I am pinned");

//        // var test = await this.ipfsEngine.FileSystem.AddFileAsync(testpath + @"test.txt");
//        // var testHash = test.Id.Hash.ToString();
//        var text = await this.ipfsEngine.FileSystem.ReadAllTextAsync(data.Id.Hash.ToString());
//        var image = await this.ipfsEngine.FileSystem.ReadFileAsync("Qmbzs7jhkBZuVixhnM3J3QhMrL6bcAoSYiRPZrdoX3DhzB");
//        Trace.WriteLine(text);
//      }
//      catch (Exception e)
//      {
//        Trace.WriteLine(e);
//      }
//    }
//  }
//}
