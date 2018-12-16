#region References

using Tangle.Net.Repository;

#endregion

namespace Chiota.Services.Iota
{
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