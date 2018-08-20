namespace Chiota.Messenger.Tests
{
  using System.Collections.Generic;
  using System.Linq;
  using System.Threading.Tasks;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Repository.DataTransfer;
  using Tangle.Net.Repository.Responses;

  /// <summary>
  /// The in memory iota repository.
  /// </summary>
  public class InMemoryIotaRepository : IIotaRepository
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryIotaRepository"/> class.
    /// </summary>
    public InMemoryIotaRepository()
    {
      this.SentBundles = new List<Bundle>();
    }

    /// <inheritdoc />
    public List<TransactionTrytes> AttachToTangle(Hash branchTransaction, Hash trunkTransaction, IEnumerable<Transaction> transactions, int minWeightMagnitude = 18)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<List<TransactionTrytes>> AttachToTangleAsync(Hash branchTransaction, Hash trunkTransaction, IEnumerable<Transaction> transactions, int minWeightMagnitude = 18)
    {
      return null;
    }

    /// <inheritdoc />
    public void BroadcastTransactions(IEnumerable<TransactionTrytes> transactions)
    {
    }

    /// <inheritdoc />
    public Task BroadcastTransactionsAsync(IEnumerable<TransactionTrytes> transactions)
    {
      return null;
    }

    /// <inheritdoc />
    public TransactionHashList FindTransactions(Dictionary<string, IEnumerable<TryteString>> parameters)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<TransactionHashList> FindTransactionsAsync(Dictionary<string, IEnumerable<TryteString>> parameters)
    {
      return null;
    }

    /// <inheritdoc />
    public TransactionHashList FindTransactionsByAddresses(IEnumerable<Address> addresses)
    {
      var transactionsList = this.SentBundles.Select(b => b.Transactions).ToList();
      var transactions = new List<Transaction>();
      foreach (var transactionList in transactionsList)
      {
        transactions.AddRange(transactionList);
      }

      var requestedTransactions = new List<Transaction>();
      foreach (var address in addresses)
      {
        requestedTransactions.AddRange(transactions.Where(t => t.Address.Value == address.Value).ToList());
      }

      return new TransactionHashList
               {
                 Hashes = requestedTransactions.Select(t => t.Hash).ToList()
               };
    }

    /// <inheritdoc />
    public async Task<TransactionHashList> FindTransactionsByAddressesAsync(IEnumerable<Address> addresses)
    {
      return this.FindTransactionsByAddresses(addresses);
    }

    /// <inheritdoc />
    public TransactionHashList FindTransactionsByApprovees(IEnumerable<Hash> approveeHashes)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<TransactionHashList> FindTransactionsByApproveesAsync(IEnumerable<Hash> approveeHashes)
    {
      return null;
    }

    /// <inheritdoc />
    public TransactionHashList FindTransactionsByBundles(IEnumerable<Hash> bundleHashes)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<TransactionHashList> FindTransactionsByBundlesAsync(IEnumerable<Hash> bundleHashes)
    {
      return null;
    }

    /// <inheritdoc />
    public TransactionHashList FindTransactionsByTags(IEnumerable<Tag> tags)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<TransactionHashList> FindTransactionsByTagsAsync(IEnumerable<Tag> tags)
    {
      return null;
    }

    /// <inheritdoc />
    public AddressWithBalances GetBalances(List<Address> addresses, int threshold = 100)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<AddressWithBalances> GetBalancesAsync(List<Address> addresses, int threshold = 100)
    {
      return null;
    }

    /// <inheritdoc />
    public InclusionStates GetInclusionStates(List<Hash> transactionHashes, IEnumerable<Hash> tips)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<InclusionStates> GetInclusionStatesAsync(List<Hash> transactionHashes, IEnumerable<Hash> tips)
    {
      return null;
    }

    /// <inheritdoc />
    public TipHashList GetTips()
    {
      return null;
    }

    /// <inheritdoc />
    public Task<TipHashList> GetTipsAsync()
    {
      return null;
    }

    /// <inheritdoc />
    public TransactionsToApprove GetTransactionsToApprove(int depth = 27)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<TransactionsToApprove> GetTransactionsToApproveAsync(int depth = 27, Hash reference = null)
    {
      return null;
    }

    /// <inheritdoc />
    public List<TransactionTrytes> GetTrytes(List<Hash> hashes)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<List<TransactionTrytes>> GetTrytesAsync(List<Hash> hashes)
    {
      return null;
    }

    /// <inheritdoc />
    public void InterruptAttachingToTangle()
    {
    }

    /// <inheritdoc />
    public Task InterruptAttachingToTangleAsync()
    {
      return null;
    }

    /// <inheritdoc />
    public void StoreTransactions(IEnumerable<TransactionTrytes> transactions)
    {
    }

    /// <inheritdoc />
    public Task StoreTransactionsAsync(IEnumerable<TransactionTrytes> transactions)
    {
      return null;
    }

    /// <inheritdoc />
    public List<Address> WereAddressesSpentFrom(List<Address> addresses)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<List<Address>> WereAddressesSpentFromAsync(List<Address> addresses)
    {
      return null;
    }

    public ConsistencyInfo CheckConsistency(List<Hash> tailHashes)
    {
      throw new System.NotImplementedException();
    }

    public Task<ConsistencyInfo> CheckConsistencyAsync(List<Hash> tailHashes)
    {
      throw new System.NotImplementedException();
    }

    /// <inheritdoc />
    public Task<bool> IsPromotableAsync(Hash tailTransaction, int depth = 6)
    {
      return null;
    }

    /// <inheritdoc />
    public Task PromoteTransactionAsync(Hash tailTransaction, int depth = 8, int minWeightMagnitude = 14, int attempts = 10)
    {
      return null;
    }

    /// <inheritdoc />
    public void BroadcastAndStoreTransactions(List<TransactionTrytes> transactions)
    {
    }

    /// <inheritdoc />
    public Task BroadcastAndStoreTransactionsAsync(List<TransactionTrytes> transactions)
    {
      return null;
    }

    /// <inheritdoc />
    public FindUsedAddressesResponse FindUsedAddressesWithTransactions(Seed seed, int securityLevel, int start)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<FindUsedAddressesResponse> FindUsedAddressesWithTransactionsAsync(Seed seed, int securityLevel, int start)
    {
      return null;
    }

    /// <inheritdoc />
    public GetAccountDataResponse GetAccountData(Seed seed, bool includeInclusionStates, int securityLevel, int addressStartIndex, int addressStopIndex = 0)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<GetAccountDataResponse> GetAccountDataAsync(Seed seed, bool includeInclusionStates, int securityLevel, int addressStartIndex, int addressStopIndex = 0)
    {
      return null;
    }

    /// <inheritdoc />
    public Bundle GetBundle(Hash transactionHash)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<Bundle> GetBundleAsync(Hash transactionHash)
    {
      return null;
    }

    /// <inheritdoc />
    public List<Bundle> GetBundles(List<Hash> transactionHashes, bool includeInclusionStates)
    {
      var requestedBundles = new List<Bundle>();
      foreach (var transactionHash in transactionHashes)
      {
        var bundlesToAdd = this.SentBundles.Where(b => b.Transactions.Any(t => t.Hash.Value == transactionHash.Value));
        requestedBundles.AddRange(bundlesToAdd);
      }

      return requestedBundles.GroupBy(b => b.Hash).Select(b => b.First()).ToList();
    }

    /// <inheritdoc />
    public async Task<List<Bundle>> GetBundlesAsync(List<Hash> transactionHashes, bool includeInclusionStates)
    {
      return this.GetBundles(transactionHashes, includeInclusionStates);
    }

    /// <inheritdoc />
    public GetInputsResponse GetInputs(Seed seed, long threshold, int securityLevel, int startIndex, int stopIndex = 0)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<GetInputsResponse> GetInputsAsync(Seed seed, long threshold, int securityLevel, int startIndex, int stopIndex = 0)
    {
      return null;
    }

    /// <inheritdoc />
    public InclusionStates GetLatestInclusion(List<Hash> hashes)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<InclusionStates> GetLatestInclusionAsync(List<Hash> hashes)
    {
      return null;
    }

    /// <inheritdoc />
    public List<Address> GetNewAddresses(Seed seed, int addressStartIndex, int count, int securityLevel)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<List<Address>> GetNewAddressesAsync(Seed seed, int addressStartIndex, int count, int securityLevel)
    {
      return null;
    }

    /// <inheritdoc />
    public List<Bundle> GetTransfers(Seed seed, int securityLevel, bool includeInclusionStates, int addressStartIndex, int addressStopIndex = 0)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<List<Bundle>> GetTransfersAsync(Seed seed, int securityLevel, bool includeInclusionStates, int addressStartIndex, int addressStopIndex = 0)
    {
      return null;
    }

    /// <inheritdoc />
    public Bundle PrepareTransfer(Seed seed, Bundle bundle, int securityLevel, Address remainderAddress = null, List<Address> inputAddresses = null)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<Bundle> PrepareTransferAsync(Seed seed, Bundle bundle, int securityLevel, Address remainderAddress = null, List<Address> inputAddresses = null)
    {
      return null;
    }

    /// <inheritdoc />
    public List<TransactionTrytes> ReplayBundle(Hash transactionHash, int depth = 27, int minWeightMagnitude = 18)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<List<TransactionTrytes>> ReplayBundleAsync(Hash transactionHash, int depth = 27, int minWeightMagnitude = 18)
    {
      return null;
    }

    /// <inheritdoc />
    public Bundle SendTransfer(
      Seed seed,
      Bundle bundle,
      int securityLevel,
      int depth = 27,
      int minWeightMagnitude = 18,
      Address remainderAddress = null,
      List<Address> inputAddresses = null)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<Bundle> SendTransferAsync(
      Seed seed,
      Bundle bundle,
      int securityLevel,
      int depth = 27,
      int minWeightMagnitude = 18,
      Address remainderAddress = null,
      List<Address> inputAddresses = null)
    {
      return null;
    }

    /// <inheritdoc />
    public List<TransactionTrytes> SendTrytes(IEnumerable<Transaction> transactions, int depth = 27, int minWeightMagnitude = 18)
    {
      var transactionTrytes = transactions.Select(t => t.ToTrytes()).ToList();
      var bundle = Bundle.FromTransactionTrytes(transactionTrytes);

      this.SentBundles.Add(bundle);

      return transactionTrytes;
    }

    public List<Bundle> SentBundles { get; set; }

    /// <inheritdoc />
    public async Task<List<TransactionTrytes>> SendTrytesAsync(IEnumerable<Transaction> transactions, int depth = 27, int minWeightMagnitude = 18)
    {
      return this.SendTrytes(transactions, depth, minWeightMagnitude);
    }

    /// <inheritdoc />
    public AddNeighborsResponse AddNeighbor(IEnumerable<Neighbor> neighbors)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<AddNeighborsResponse> AddNeighborAsync(IEnumerable<Neighbor> neighbors)
    {
      return null;
    }

    /// <inheritdoc />
    public NeighborList GetNeighbors()
    {
      return null;
    }

    /// <inheritdoc />
    public Task<NeighborList> GetNeighborsAsync()
    {
      return null;
    }

    /// <inheritdoc />
    public NodeInfo GetNodeInfo()
    {
      return null;
    }

    /// <inheritdoc />
    public Task<NodeInfo> GetNodeInfoAsync()
    {
      return null;
    }

    /// <inheritdoc />
    public RemoveNeighborsResponse RemoveNeighbors(IEnumerable<Neighbor> neighbors)
    {
      return null;
    }

    /// <inheritdoc />
    public Task<RemoveNeighborsResponse> RemoveNeighborsAsync(IEnumerable<Neighbor> neighbors)
    {
      return null;
    }
  }
}
