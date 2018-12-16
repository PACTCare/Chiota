#region Refgerences

using System.Threading.Tasks;

#endregion

namespace Chiota.Services
{
    public interface IScreenshot
    {
        Task<string> CaptureAndSaveAsync();

        Task<byte[]> CaptureAsync();
    }
}
