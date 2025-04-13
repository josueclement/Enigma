using Enigma.WpfApp.ViewModels.Pages;

namespace Enigma.WpfApp.Views.Pages;

public partial class StreamCiphersPage
{
    public StreamCiphersPage(StreamCiphersPageViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = this;
    }
    
    public StreamCiphersPageViewModel ViewModel { get; }
}