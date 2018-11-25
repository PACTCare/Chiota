using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Services
{
    public interface INotification
    {
        void Show(string header, string text);
    }
}
