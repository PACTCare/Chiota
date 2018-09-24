using Chiota.ViewModels.Classes;

namespace Chiota.Views.Authentication
{
    using Xamarin.Forms;
    using Xamarin.Forms.Xaml;

    /// <inheritdoc />
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class LogInView : ContentPage
    {
        public LogInView()
        {
            InitializeComponent();

            if (BindingContext is BaseViewModel viewModel)
                viewModel.Setup(this);
        }
    }
}