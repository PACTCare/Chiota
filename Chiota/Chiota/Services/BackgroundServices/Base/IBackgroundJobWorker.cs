namespace Chiota.Services.BackgroundServices.Base
{
    public interface IBackgroundJobWorker
    {
        void Init(params object[] data);

        void Run<T>(params object[] data) where T : BaseBackgroundJob;

        void Dispose();
    }
}
