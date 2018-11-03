using System;

namespace Chiota.Services.BackgroundServices.Base
{
    public interface IBackgroundWorker
    {
        void Disposed();

        void Add<T>(string jobId) where T : BaseBackgroundJob;
        void Add<T>(string jobId, TimeSpan refreshTime) where T : BaseBackgroundJob;

        void Add<T>(string jobId, object data) where T : BaseBackgroundJob;
        void Add<T>(string jobId, object data, TimeSpan refreshTime) where T : BaseBackgroundJob;

        void Remove<T>(string jobId) where T : BaseBackgroundJob;
    }
}
