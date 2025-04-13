using Enigma.WpfApp.ViewModels.Pages;

namespace Enigma.WpfApp.Views.Pages;

public partial class KdfPage
{
    public KdfPage(KdfPageViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = this;
    }
    
    public KdfPageViewModel ViewModel { get; }
}