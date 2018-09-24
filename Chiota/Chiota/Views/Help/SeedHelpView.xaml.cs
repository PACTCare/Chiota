using Chiota.ViewModels.Classes;

namespace Chiota.Views.Help
{
    using Xamarin.Forms;
    using Xamarin.Forms.Xaml;

    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class SeedHelpView : ContentPage
    {
        public SeedHelpView()
        {
            InitializeComponent();

            if (BindingContext is BaseViewModel viewModel)
                viewModel.Setup(this);
        }
    }
}