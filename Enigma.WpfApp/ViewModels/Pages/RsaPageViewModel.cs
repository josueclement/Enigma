using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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
        // ContentDialogResult result = await _dialogService.ShowSimpleDialogAsync(
        //     new SimpleContentDialogCreateOptions()
        //     {
        //         Title = "Save your work?",
        //         Content = null,
        //         PrimaryButtonText = "Save",
        //         SecondaryButtonText = "Don't Save",
        //         CloseButtonText = "Cancel",
        //     }
        // );
        var dialog = new RsaKeyPairGenerationDialog(_dialogService.GetDialogHost());
        _ = await dialog.ShowAsync();
    }
}