namespace Chiota.Services.AvatarStorage
{
  using System.Threading.Tasks;

  public interface IAvatarStorage
  {
    Task<string> UploadEncryptedAsync(string name, byte[] imageAsBytes);
  }
}
