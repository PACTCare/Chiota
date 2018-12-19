using Chiota.UWP.Services.BackgroundService;

namespace Chiota.UWP
{
    public sealed partial class MainPage
    {
        public MainPage()
        {
            this.InitializeComponent();

            this.LoadApplication(new Chiota.App());

            //Init the background services.
            Xamarin.Forms.DependencyService.Get<BackgroundJobWorker>().Init();
        }
    }
}