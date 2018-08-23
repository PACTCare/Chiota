namespace Chiota.Messenger.Usecase
{
  using System.Threading.Tasks;

  /// <summary>
  /// Usecase interface as described by Robert C. Martin here: https://www.youtube.com/watch?v=Nsjsiz2A9mg
  /// </summary>
  /// <typeparam name="TRequest">
  /// The usecases request
  /// </typeparam>
  /// <typeparam name="TResponse">
  /// The usecases response
  /// </typeparam>
  public interface IUsecaseInteractor<in TRequest, TResponse>
  {
    /// <summary>
    /// The execute.
    /// </summary>
    /// <param name="request">
    /// The request.
    /// </param>
    /// <returns>
    /// The <see cref="TResponse"/>.
    /// </returns>
    Task<TResponse> ExecuteAsync(TRequest request);
  }
}