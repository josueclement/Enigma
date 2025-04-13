using Enigma.WpfApp.ViewModels.Pages;

namespace Enigma.WpfApp.Views.Pages;

public partial class SettingsPage
{
    public SettingsPage(SettingsPageViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = this;
    }
    
    public SettingsPageViewModel ViewModel { get; }
}