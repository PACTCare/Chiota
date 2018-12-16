#region References

using System.Threading.Tasks;

#endregion

namespace Chiota.Services
{
    public interface IImageQrCodeReader
    {
        Task<string> ReadAsync(byte[] data);
    }
}
