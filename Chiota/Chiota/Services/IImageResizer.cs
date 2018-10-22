using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Chiota.Services
{
    public interface IImageResizer
    {
        Task<byte[]> Resize(byte[] imageData, float size);
    }
}
