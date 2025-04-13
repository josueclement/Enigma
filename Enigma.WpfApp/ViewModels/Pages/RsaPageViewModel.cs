using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Enigma.WpfApp.ViewModels.Dialogs;
using Enigma.WpfApp.Views.Dialogs;
using Wpf.Ui;
using Wpf.Ui.Controls;
using Wpf.Ui.Extensions;

namespace Enigma.WpfApp.ViewModels.Pages;

public class RsaPageViewModel : ObservableObject
{
    private readonly IContentDialogService _dialogService;

    public RsaPageViewModel(IContentDialogService dialogService)
    {
        _dialogService = dialogService;
        GenerateKeyPairCommand = new AsyncRelayCommand(GenerateKeyPairAsync);
    }
    
    public AsyncRelayCommand GenerateKeyPairCommand { get; }

    public async Task GenerateKeyPairAsync()
    {
        var keyGenerationDialog = new RsaKeyPairGenerationDialog();
        var vm = new RsaKeyPairGenerationDialogViewModel();
        keyGenerationDialog.DataContext = vm;
        
        var dialog = new ContentDialog(_dialogService.GetDialogHost()) // Use GetDialogHost()
        {
            Title = "Generate RSA Key Pair",
            Content = keyGenerationDialog, // Set our UserControl as content
            PrimaryButtonText = "Generate",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };
        
        var result = await dialog.ShowAsync();

        var keySize = vm.KeySize;
    }
}