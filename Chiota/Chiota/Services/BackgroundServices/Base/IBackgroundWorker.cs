namespace Chiota.Services.BackgroundServices.Base
{
    public interface IBackgroundWorker
    {
        void Start<T>(params object[] objects) where T : BaseBackgroundService;
    }
}
