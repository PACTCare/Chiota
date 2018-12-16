#region References

using System.Threading.Tasks;

#endregion

namespace Chiota.Services
{
    public interface IImageResizer
    {
        Task<byte[]> Resize(byte[] imageData, float size);
    }
}
