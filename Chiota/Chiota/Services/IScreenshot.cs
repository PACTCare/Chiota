using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Chiota.Services
{
    public interface IScreenshot
    {
        Task<string> CaptureAndSaveAsync();

        Task<byte[]> CaptureAsync();
    }
}
