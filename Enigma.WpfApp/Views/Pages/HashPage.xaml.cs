using Enigma.WpfApp.ViewModels.Pages;

namespace Enigma.WpfApp.Views.Pages;

public partial class HashPage
{
    public HashPage(HashPageViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = this;
    }
    
    public HashPageViewModel ViewModel { get; }
}