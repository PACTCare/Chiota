namespace Chiota.Services.BackgroundServices.Base
{
    public interface IBackgroundJobWorker
    {
        void Init(params object[] data);

        void Add<T>(params object[] data) where T : BaseBackgroundJob;
        void Clear();

        void Register();

        void Dispose();
    }
}
