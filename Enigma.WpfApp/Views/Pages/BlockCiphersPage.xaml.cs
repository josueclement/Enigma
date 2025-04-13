using Enigma.WpfApp.ViewModels.Pages;

namespace Enigma.WpfApp.Views.Pages;

public partial class BlockCiphersPage
{
    public BlockCiphersPage(BlockCiphersPageViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = this;
    }
    
    public BlockCiphersPageViewModel ViewModel { get; }
}