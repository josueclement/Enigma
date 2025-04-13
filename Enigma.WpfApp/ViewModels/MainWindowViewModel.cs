using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Enigma.WpfApp.Views.Pages;
using Wpf.Ui.Controls;

namespace Enigma.WpfApp.ViewModels;

public class MainWindowViewModel : ObservableObject
{
    public MainWindowViewModel()
    {
        if (!_isInitialized) 
            Initialize();
    }
    
    private bool _isInitialized = false;
    
    public ObservableCollection<object> NavigationItems { get; } = [];
    public ObservableCollection<object> FooterNavigationItems { get; } = [];

    private void Initialize()
    {
        NavigationItems.Add(new NavigationViewItem
        {
            Content = "Home",
            Icon = new SymbolIcon { Symbol = SymbolRegular.Home24 },
            TargetPageType = typeof(HomePage),
            ToolTip = "Home"
        });
        NavigationItems.Add(new NavigationViewItem
        {
            Content = "RSA",
            Icon = new SymbolIcon { Symbol = SymbolRegular.KeyMultiple20 },
            TargetPageType = typeof(RsaPage),
            ToolTip = "RSA"
        });
        NavigationItems.Add(new NavigationViewItem
        {
            Content = "ML-DSA",
            Icon = new SymbolIcon { Symbol = SymbolRegular.KeyMultiple20 },
            TargetPageType = typeof(MlDsaPage),
            ToolTip = "ML-DSA"
        });
        NavigationItems.Add(new NavigationViewItem
        {
            Content = "ML-KEM",
            Icon = new SymbolIcon { Symbol = SymbolRegular.KeyMultiple20 },
            TargetPageType = typeof(MlKemPage),
            ToolTip = "ML-KEM"
        });
        NavigationItems.Add(new NavigationViewItem
        {
            Content = "Block ciphers",
            Icon = new SymbolIcon { Symbol = SymbolRegular.Key20 },
            TargetPageType = typeof(BlockCiphersPage),
            ToolTip = "Block ciphers"
        });
        NavigationItems.Add(new NavigationViewItem
        {
            Content = "Stream ciphers",
            Icon = new SymbolIcon { Symbol = SymbolRegular.Key20 },
            TargetPageType = typeof(StreamCiphersPage),
            ToolTip = "Stream ciphers"
        });
        NavigationItems.Add(new NavigationViewItem
        {
            Content = "KDF",
            Icon = new SymbolIcon { Symbol = SymbolRegular.Key20 },
            TargetPageType = typeof(KdfPage),
            ToolTip = "KDF"
        });
        NavigationItems.Add(new NavigationViewItem
        {
            Content = "Hash",
            Icon = new SymbolIcon { Symbol = SymbolRegular.Key20 },
            TargetPageType = typeof(HashPage),
            ToolTip = "Hash"
        });
        
        FooterNavigationItems.Add(new NavigationViewItem
        {
            Content = "Settings",
            Icon = new SymbolIcon { Symbol = SymbolRegular.Settings24 },
            TargetPageType = typeof(SettingsPage),
            ToolTip = "Settings"
        });
        
        _isInitialized = true;
    }
}