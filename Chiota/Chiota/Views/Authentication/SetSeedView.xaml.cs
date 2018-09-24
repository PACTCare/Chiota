using Chiota.ViewModels.Classes;

namespace Chiota.Views.Authentication
{
    using Xamarin.Forms;
    using Xamarin.Forms.Xaml;

    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class SetSeedView : ContentPage
    {
        public SetSeedView()
        {
            InitializeComponent();

            if (BindingContext is BaseViewModel viewModel)
                viewModel.Setup(this);
        }
    }
}