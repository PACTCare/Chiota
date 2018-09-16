namespace Chiota.Services.Iota
{
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Persistence;
  using Chiota.Services.DependencyInjection;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Utils;

  public class TangleMessenger
  {
    private const int Depth = 8;

    private readonly Seed seed;

    public TangleMessenger(Seed seed, int minWeightMagnitude = 14)
    {
      this.seed = seed;
      this.MinWeight = minWeightMagnitude;
      this.Repository = DependencyResolver.Resolve<IIotaRepository>();
      this.ShortStorageAddressList = new List<string>();
      this.TransactionCache = DependencyResolver.Resolve<AbstractSqlLiteTransactionCache>();
    }

    public List<string> ShortStorageAddressList { get; set; }

    private int MinWeight { get; }

    private IIotaRepository Repository { get; }

    private AbstractSqlLiteTransactionCache TransactionCache { get; }

    public async Task<bool> SendMessageAsync(TryteString message, string address, int retryNumber = 3)
    {
      var roundNumber = 0;
      while (roundNumber < retryNumber)
      {
        // this.UpdateNode(roundNumber);
        var bundle = new Bundle();
        bundle.AddTransfer(CreateTransfer(message, address));

        try
        {
          await this.Repository.SendTransferAsync(this.seed, bundle, SecurityLevel.Medium, Depth, this.MinWeight);
          return true;
        }
        catch (Exception e)
        {
          Trace.WriteLine(e);
          roundNumber++;
        }
      }

      return false;
    }

    private static Transfer CreateTransfer(TryteString message, string address)
    {
      return new Transfer
               {
                 Address = new Address(address), Message = message, Tag = new Tag(ChiotaConstants.Tag), Timestamp = Timestamp.UnixSecondsTimestamp
               };
    }
  }
}