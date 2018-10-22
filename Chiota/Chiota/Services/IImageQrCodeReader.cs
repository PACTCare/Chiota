using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Chiota.Services
{
    public interface IImageQrCodeReader
    {
        Task<string> ReadAsync(byte[] data);
    }
}
