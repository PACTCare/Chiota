using Chiota.ViewModels.Classes;

namespace Chiota.Views.BackUp
{
    using Xamarin.Forms;
    using Xamarin.Forms.Xaml;

    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class QrCodeView : ContentPage
    {
        public QrCodeView()
        {
            InitializeComponent();

            if (BindingContext is BaseViewModel viewModel)
                viewModel.Setup(this);
        }
    }
}