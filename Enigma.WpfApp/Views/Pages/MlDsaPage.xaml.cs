using Enigma.WpfApp.ViewModels.Pages;

namespace Enigma.WpfApp.Views.Pages;

public partial class MlDsaPage
{
    public MlDsaPage(MlDsaPageViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = this;
    }
    
    public MlDsaPageViewModel ViewModel { get; }
}