namespace Chiota.Services.BackgroundServices.Base
{
    public interface IBackgroundJobWorker
    {
        void Init(params object[] data);

        void Add<T>(int id, params object[] data) where T : BaseBackgroundJob;
        void Remove(int id);

        void Dispose();
    }
}
