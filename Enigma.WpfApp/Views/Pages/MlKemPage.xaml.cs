using Enigma.WpfApp.ViewModels.Pages;

namespace Enigma.WpfApp.Views.Pages;

public partial class MlKemPage
{
    public MlKemPage(MlKemPageViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = this;
    }
    
    public MlKemPageViewModel ViewModel { get; }
}