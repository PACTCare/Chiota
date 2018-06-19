namespace Chiota.Services.AvatarStorage
{
  using System.Threading.Tasks;

  /// <summary>
  /// The AvatarStorage interface.
  /// </summary>
  public interface IAvatarStorage
  {
    /// <summary>
    /// The upload encrypted async.
    /// </summary>
    /// <param name="name">
    /// The name.
    /// </param>
    /// <param name="imageAsBytes">
    /// The image as bytes.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task<string> UploadEncryptedAsync(string name, byte[] imageAsBytes);
  }
}