using Enigma.WpfApp.ViewModels.Pages;

namespace Enigma.WpfApp.Views.Pages;

public partial class HomePage
{
    public HomePage(HomePageViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = this;
    }

    public HomePageViewModel ViewModel { get; }
}