using Chiota.ViewModels.Classes;

namespace Chiota.Views.BackUp
{
    using Xamarin.Forms;
    using Xamarin.Forms.Xaml;

    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class WriteSeedView : ContentPage
    {
        public WriteSeedView()
        {
            InitializeComponent();

            if (BindingContext is BaseViewModel viewModel)
                viewModel.Setup(this);
        }
    }
}