namespace Chiota.Services.AvatarStorage
{
  using System.IO;
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
    /// <param name="imageAsStream">
    /// The image as stream.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task<string> UploadEncryptedAsync(string name, Stream imageAsStream);
  }
}