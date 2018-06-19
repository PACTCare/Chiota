namespace Chiota.Services.Iota.Repository
{
  using Tangle.Net.Repository;

  /// <summary>
  /// The RepositoryFactory interface.
  /// </summary>
  public interface IRepositoryFactory
  {
    /// <summary>
    /// The create.
    /// </summary>
    /// <param name="roundNumber">
    /// The round number.
    /// </param>
    /// <returns>
    /// The <see cref="RestIotaRepository"/>.
    /// </returns>
    RestIotaRepository Create(int roundNumber = 0);
  }
}